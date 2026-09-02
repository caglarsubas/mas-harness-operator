package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

const SchemaVersion = "harness.planeon.ai/foundation-apply-evidence/v1alpha1"

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Input struct {
	OrganizationID  string
	InstallationID  string
	Generation      int64
	ProfileDigest   string
	BundleDigest    string
	ReleaseDigest   string
	PlanDigest      string
	ReceiptDigest   string
	InventoryDigest string
	WaveCount       int
	ResourceCount   int
	Result          string
	ReasonCode      string
	StartedAt       string
	CompletedAt     string
}

type Record struct {
	SchemaVersion   string `json:"schemaVersion"`
	OrganizationID  string `json:"organizationId"`
	InstallationID  string `json:"installationId"`
	Generation      int64  `json:"generation"`
	ProfileDigest   string `json:"profileDigest"`
	BundleDigest    string `json:"bundleDigest"`
	ReleaseDigest   string `json:"releaseDigest"`
	PlanDigest      string `json:"planDigest"`
	ReceiptDigest   string `json:"verificationReceiptDigest"`
	InventoryDigest string `json:"inventoryDigest"`
	WaveCount       int    `json:"waveCount"`
	ResourceCount   int    `json:"resourceCount"`
	Result          string `json:"result"`
	ReasonCode      string `json:"reasonCode"`
	StartedAt       string `json:"startedAt"`
	CompletedAt     string `json:"completedAt"`
	EvidenceDigest  string `json:"evidenceDigest"`
}

func Build(input Input) (Record, error) {
	for _, digest := range []string{input.ProfileDigest, input.BundleDigest, input.ReleaseDigest, input.PlanDigest, input.ReceiptDigest, input.InventoryDigest} {
		if !digestPattern.MatchString(digest) {
			return Record{}, errors.New("EVIDENCE_DIGEST_INVALID")
		}
	}
	started, firstErr := exactTime(input.StartedAt)
	completed, secondErr := exactTime(input.CompletedAt)
	if firstErr != nil || secondErr != nil || completed.Before(started) {
		return Record{}, errors.New("EVIDENCE_TIME_INVALID")
	}
	if input.OrganizationID == "" || input.InstallationID == "" || input.Generation < 1 || input.WaveCount < 1 || input.ResourceCount < 1 || input.Result != "FOUNDATION_APPLIED" || input.ReasonCode != "FOUNDATION_APPLIED_AWAITING_HEALTH" {
		return Record{}, errors.New("EVIDENCE_INPUT_INVALID")
	}
	record := Record{
		SchemaVersion: SchemaVersion, OrganizationID: input.OrganizationID, InstallationID: input.InstallationID,
		Generation: input.Generation, ProfileDigest: input.ProfileDigest, BundleDigest: input.BundleDigest,
		ReleaseDigest: input.ReleaseDigest, PlanDigest: input.PlanDigest, ReceiptDigest: input.ReceiptDigest,
		InventoryDigest: input.InventoryDigest, WaveCount: input.WaveCount, ResourceCount: input.ResourceCount,
		Result: input.Result, ReasonCode: input.ReasonCode, StartedAt: input.StartedAt, CompletedAt: input.CompletedAt,
	}
	payload, _ := json.Marshal(record)
	digest := sha256.Sum256(payload)
	record.EvidenceDigest = "sha256:" + hex.EncodeToString(digest[:])
	return record, nil
}

func Canonical(record Record) []byte {
	data, _ := json.Marshal(record)
	return data
}

func exactTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond() != 0 || parsed.Format(time.RFC3339) != value {
		return time.Time{}, errors.New("time is not canonical UTC")
	}
	return parsed, nil
}
