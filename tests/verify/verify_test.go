package verify_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/caglarsubas/mas-harness-operator/internal/preflight"
	"github.com/caglarsubas/mas-harness-operator/internal/verify"
)

type sink struct{ calls int }

func (value *sink) Admit(verify.Receipt) error { value.calls++; return nil }

func root(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	value, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", "..", "fixtures", "preflight"))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func inputs(t *testing.T) (preflight.Request, preflight.Observation) {
	t.Helper()
	var request preflight.Request
	var observation preflight.Observation
	for name, target := range map[string]any{"request.json": &request, "observation-supported.json": &observation} {
		data, err := os.ReadFile(filepath.Join(root(t), name))
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytesReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(target); err != nil {
			t.Fatal(err)
		}
	}
	return request, observation
}

type reader struct {
	data   []byte
	offset int
}

func bytesReader(data []byte) io.Reader { return &reader{data: data} }
func (value *reader) Read(target []byte) (int, error) {
	if value.offset == len(value.data) {
		return 0, io.EOF
	}
	count := copy(target, value.data[value.offset:])
	value.offset += count
	return count, nil
}

func copyTree(t *testing.T) string {
	t.Helper()
	source := filepath.Join(root(t), "signed-valid")
	destination := filepath.Join(t.TempDir(), "bundle")
	if err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err = io.Copy(output, input); err != nil {
			output.Close()
			return err
		}
		return output.Close()
	}); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(destination)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestValidFixtureIsDeterministicAndAdmittedOnce(t *testing.T) {
	request, observation := inputs(t)
	verifier := verify.Verifier{MinimumTrustSequence: 2}
	firstSink := &sink{}
	first, err := verifier.VerifyBeforeApply(context.Background(), filepath.Join(root(t), "signed-valid"), "2026-09-02T12:00:00Z", request, observation, firstSink)
	if err != nil {
		t.Fatal(err)
	}
	second, err := verifier.Verify(context.Background(), filepath.Join(root(t), "signed-valid"), "2026-09-02T12:00:00Z", request, observation)
	if err != nil {
		t.Fatal(err)
	}
	if firstSink.calls != 1 || first.State != "VERIFIED" || first.ComponentCount != 2 || len(first.Conditions) != 8 || !reflect.DeepEqual(first, second) {
		t.Fatalf("non-deterministic receipt or sink: %+v calls=%d", first, firstSink.calls)
	}
}

func TestPreflightBlocksBeforeMutation(t *testing.T) {
	request, observation := inputs(t)
	observation.Architecture = "amd64"
	target := &sink{}
	_, err := (verify.Verifier{MinimumTrustSequence: 2}).VerifyBeforeApply(context.Background(), filepath.Join(root(t), "signed-valid"), "2026-09-02T12:00:00Z", request, observation, target)
	if verify.Reason(err) != "PREFLIGHT_BLOCKED" || target.calls != 0 {
		t.Fatalf("reason=%s calls=%d", verify.Reason(err), target.calls)
	}
}

func TestBundleTamperingAndClosureBlockBeforeMutation(t *testing.T) {
	request, observation := inputs(t)
	vectors := []struct {
		name, expected string
		mutate         func(*testing.T, string)
	}{
		{"extra", "BUNDLE_FILE_CLOSURE_INVALID", func(t *testing.T, path string) {
			if err := os.WriteFile(filepath.Join(path, "extra.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"blob", "OCI_BLOB_DIGEST_MISMATCH", func(t *testing.T, path string) {
			matches, err := filepath.Glob(filepath.Join(path, "oci/blobs/sha256/*"))
			if err != nil || len(matches) == 0 {
				t.Fatal("blob absent")
			}
			if err := os.WriteFile(matches[0], []byte("tampered"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"manifest", "JSON_DOCUMENT_INVALID", func(t *testing.T, path string) {
			if err := os.WriteFile(filepath.Join(path, "release-manifest.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"noncanonical", "JSON_NOT_CANONICAL", func(t *testing.T, path string) {
			name := filepath.Join(path, "signed-release.json")
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, append(data, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"incomplete", "BUNDLE_FILE_INVALID", func(t *testing.T, path string) {
			if err := os.Remove(filepath.Join(path, "approval.sigstore.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", "BUNDLE_TREE_INVALID", func(t *testing.T, path string) {
			if err := os.Symlink("bundle.lock.json", filepath.Join(path, "linked.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", "BUNDLE_FILE_INVALID", func(t *testing.T, path string) {
			if err := os.Link(filepath.Join(path, "bundle.lock.json"), filepath.Join(path, "hard.json")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			bundle := copyTree(t)
			vector.mutate(t, bundle)
			target := &sink{}
			_, err := (verify.Verifier{MinimumTrustSequence: 2}).VerifyBeforeApply(context.Background(), bundle, "2026-09-02T12:00:00Z", request, observation, target)
			if verify.Reason(err) != vector.expected || target.calls != 0 {
				t.Fatalf("reason=%s want=%s calls=%d", verify.Reason(err), vector.expected, target.calls)
			}
		})
	}
}

func TestTrustTimeSequenceAndPlatformClosureBlock(t *testing.T) {
	request, observation := inputs(t)
	vectors := []struct {
		name, expected, when string
		minimum              int
		mutate               func(*preflight.Request, *preflight.Observation)
	}{
		{"stale", "TRUST_SEQUENCE_STALE", "2026-09-02T12:00:00Z", 3, func(*preflight.Request, *preflight.Observation) {}},
		{"expired", "TRUST_KEYS_INVALID", "2027-01-01T00:00:00Z", 2, func(*preflight.Request, *preflight.Observation) {}},
		{"not-yet-valid", "TRUST_KEYS_INVALID", "2026-08-31T23:59:59Z", 2, func(*preflight.Request, *preflight.Observation) {}},
		{"platform-closure", "PLATFORM_CLOSURE_INVALID", "2026-09-02T12:00:00Z", 2, func(request *preflight.Request, observation *preflight.Observation) {
			request.Architecture = "amd64"
			observation.Architecture = "amd64"
		}},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			candidateRequest, candidateObservation := request, observation
			candidateRequest.SelectedModules = append([]string(nil), request.SelectedModules...)
			candidateObservation.StorageClasses = append([]string(nil), observation.StorageClasses...)
			vector.mutate(&candidateRequest, &candidateObservation)
			target := &sink{}
			_, err := (verify.Verifier{MinimumTrustSequence: vector.minimum}).VerifyBeforeApply(context.Background(), filepath.Join(root(t), "signed-valid"), vector.when, candidateRequest, candidateObservation, target)
			if verify.Reason(err) != vector.expected || target.calls != 0 {
				t.Fatalf("reason=%s want=%s calls=%d", verify.Reason(err), vector.expected, target.calls)
			}
		})
	}
}
