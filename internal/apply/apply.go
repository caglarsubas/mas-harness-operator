package apply

import (
	"context"
	"errors"
	"regexp"
	"time"
)

const FieldManager = "planeon-foundation-v1"

var (
	digestPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uidPattern             = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
	resourceVersionPattern = regexp.MustCompile(`^[1-9][0-9]*$`)
)

type Identity struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

func (identity Identity) Key() string {
	return identity.APIVersion + "/" + identity.Kind + "/" + identity.Namespace + "/" + identity.Name
}

type Request struct {
	Identity       Identity `json:"identity"`
	Manifest       []byte   `json:"-"`
	ManifestDigest string   `json:"manifestDigest"`
	FieldManager   string   `json:"fieldManager"`
	Force          bool     `json:"force"`
	DryRun         bool     `json:"dryRun"`
}

type Receipt struct {
	Identity               Identity `json:"identity"`
	UID                    string   `json:"uid"`
	ResourceVersion        string   `json:"resourceVersion"`
	ObservedManifestDigest string   `json:"observedManifestDigest"`
	AppliedAt              string   `json:"appliedAt"`
}

type Port interface {
	Apply(context.Context, Request) (Receipt, error)
}

type Refusal struct{ Code string }

func (refusal Refusal) Error() string { return refusal.Code }

func Refuse(code string) error { return Refusal{Code: code} }

func ValidateReceipt(request Request, receipt Receipt) error {
	if receipt.Identity != request.Identity || !uidPattern.MatchString(receipt.UID) || !resourceVersionPattern.MatchString(receipt.ResourceVersion) {
		return Refuse("APPLY_RESPONSE_IDENTITY_INVALID")
	}
	if request.FieldManager != FieldManager || request.Force || request.DryRun || !digestPattern.MatchString(request.ManifestDigest) {
		return Refuse("APPLY_REQUEST_INVALID")
	}
	if receipt.ObservedManifestDigest != request.ManifestDigest {
		return Refuse("APPLY_RESPONSE_DRIFT")
	}
	parsed, err := time.Parse(time.RFC3339, receipt.AppliedAt)
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond() != 0 || parsed.Format(time.RFC3339) != receipt.AppliedAt {
		return Refuse("APPLY_RESPONSE_TIME_INVALID")
	}
	return nil
}

func Reason(err error) string {
	var refusal Refusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return "APPLY_BACKEND_UNAVAILABLE"
}
