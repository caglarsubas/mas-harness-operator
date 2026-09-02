package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"

	"github.com/caglarsubas/mas-harness-operator/internal/apply"
)

const SchemaVersion = "harness.planeon.ai/foundation-generation-inventory/v1alpha1"

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	idPattern     = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$`)
)

type Binding struct {
	OrganizationID            string `json:"organizationId"`
	InstallationID            string `json:"installationId"`
	Generation                int64  `json:"generation"`
	TargetNamespace           string `json:"targetNamespace"`
	ProfileDigest             string `json:"profileDigest"`
	BundleDigest              string `json:"bundleDigest"`
	ReleaseDigest             string `json:"releaseDigest"`
	PlanDigest                string `json:"planDigest"`
	VerificationReceiptDigest string `json:"verificationReceiptDigest"`
}

type ResourceRecord struct {
	WaveID                 string         `json:"waveId"`
	Identity               apply.Identity `json:"identity"`
	DesiredManifestDigest  string         `json:"desiredManifestDigest"`
	ObservedManifestDigest string         `json:"observedManifestDigest"`
	UID                    string         `json:"uid"`
	ResourceVersion        string         `json:"resourceVersion"`
	AppliedAt              string         `json:"appliedAt"`
	State                  string         `json:"state"`
}

type GenerationInventory struct {
	SchemaVersion string           `json:"schemaVersion"`
	Binding       Binding          `json:"binding"`
	State         string           `json:"state"`
	NextWave      int              `json:"nextWave"`
	NextResource  int              `json:"nextResource"`
	NextIdentity  string           `json:"nextIdentity"`
	Records       []ResourceRecord `json:"records"`
}

type Store interface {
	Load(context.Context, string) (GenerationInventory, uint64, bool, error)
	CompareAndSwap(context.Context, string, uint64, GenerationInventory) (uint64, error)
}

type Refusal struct{ Code string }

func (refusal Refusal) Error() string { return refusal.Code }

func Refuse(code string) error { return Refusal{Code: code} }

func Key(binding Binding) string {
	return binding.OrganizationID + "/" + binding.InstallationID + "/" + jsonNumber(binding.Generation)
}

func Validate(value GenerationInventory, expected Binding) error {
	if value.SchemaVersion != SchemaVersion || value.Binding != expected {
		return Refuse("INVENTORY_BINDING_DRIFT")
	}
	if value.State != "APPLYING" && value.State != "WAVE_APPLYING" && value.State != "STATUS_PENDING" && value.State != "COMPLETE" {
		return Refuse("INVENTORY_STATE_INVALID")
	}
	if value.NextWave < 0 || value.NextResource < 0 {
		return Refuse("INVENTORY_CURSOR_INVALID")
	}
	seen := map[string]struct{}{}
	for _, record := range value.Records {
		key := record.Identity.Key()
		if key == "///" || record.WaveID == "" || record.State != "APPLIED" || !digestPattern.MatchString(record.DesiredManifestDigest) || record.DesiredManifestDigest != record.ObservedManifestDigest || record.UID == "" || record.ResourceVersion == "" || record.AppliedAt == "" {
			return Refuse("INVENTORY_RECORD_INVALID")
		}
		request := apply.Request{Identity: record.Identity, ManifestDigest: record.DesiredManifestDigest, FieldManager: apply.FieldManager}
		receipt := apply.Receipt{Identity: record.Identity, UID: record.UID, ResourceVersion: record.ResourceVersion, ObservedManifestDigest: record.ObservedManifestDigest, AppliedAt: record.AppliedAt}
		if err := apply.ValidateReceipt(request, receipt); err != nil {
			return Refuse("INVENTORY_RECORD_INVALID")
		}
		if _, duplicate := seen[key]; duplicate {
			return Refuse("INVENTORY_RECORD_DUPLICATED")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func ProjectionDigest(value GenerationInventory) string {
	payload := struct {
		SchemaVersion string           `json:"schemaVersion"`
		Binding       Binding          `json:"binding"`
		Records       []ResourceRecord `json:"records"`
	}{SchemaVersion: value.SchemaVersion, Binding: value.Binding, Records: append([]ResourceRecord(nil), value.Records...)}
	data, _ := json.Marshal(payload)
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func Canonical(value GenerationInventory) []byte {
	data, _ := json.Marshal(value)
	return data
}

func Reason(err error) string {
	var refusal Refusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return "INVENTORY_BACKEND_UNAVAILABLE"
}

func RecordsSorted(records []ResourceRecord) bool {
	return sort.SliceIsSorted(records, func(left, right int) bool {
		return records[left].Identity.Key() < records[right].Identity.Key()
	})
}

func jsonNumber(value int64) string {
	data, _ := json.Marshal(value)
	return string(data)
}
