package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/caglarsubas/mas-harness-operator/internal/preflight"
	"github.com/caglarsubas/mas-harness-operator/internal/verify"
)

const minimumTrustSequence = 2

type arguments struct {
	request, observation, bundleRoot, verificationTime, output string
}

func parse(raw []string) (arguments, error) {
	if len(raw) != 10 {
		return arguments{}, errors.New("ARGUMENTS_INVALID")
	}
	values := map[string]string{}
	allowed := map[string]struct{}{"--request": {}, "--observation": {}, "--bundle-root": {}, "--verification-time": {}, "--output": {}}
	for index := 0; index < len(raw); index += 2 {
		name, value := raw[index], raw[index+1]
		if _, ok := allowed[name]; !ok || value == "" || strings.ContainsRune(value, '\x00') {
			return arguments{}, errors.New("ARGUMENTS_INVALID")
		}
		if _, duplicate := values[name]; duplicate {
			return arguments{}, errors.New("ARGUMENTS_INVALID")
		}
		values[name] = value
	}
	if len(values) != len(allowed) {
		return arguments{}, errors.New("ARGUMENTS_INVALID")
	}
	return arguments{request: values["--request"], observation: values["--observation"], bundleRoot: values["--bundle-root"], verificationTime: values["--verification-time"], output: values["--output"]}, nil
}

func canonicalInput(path string, target any) error {
	if !filepath.IsAbs(path) {
		return errors.New("INPUT_PATH_INVALID")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("INPUT_PATH_INVALID")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return errors.New("INPUT_PATH_INVALID")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New("INPUT_READ_FAILED")
	}
	canonicalDecoder := json.NewDecoder(bytes.NewReader(data))
	canonicalDecoder.UseNumber()
	var generic map[string]any
	if err := canonicalDecoder.Decode(&generic); err != nil || generic == nil {
		return errors.New("INPUT_JSON_INVALID")
	}
	var trailing any
	if err := canonicalDecoder.Decode(&trailing); err != io.EOF {
		return errors.New("INPUT_JSON_INVALID")
	}
	canonical, err := json.Marshal(generic)
	if err != nil || !bytes.Equal(canonical, data) {
		return errors.New("INPUT_JSON_NOT_CANONICAL")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("INPUT_JSON_INVALID")
	}
	return nil
}

func atomicReceipt(path string, receipt verify.Receipt) error {
	if !filepath.IsAbs(path) {
		return errors.New("OUTPUT_PATH_INVALID")
	}
	if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
		return errors.New("OUTPUT_ALREADY_EXISTS")
	}
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != filepath.Clean(parent) {
		return errors.New("OUTPUT_PARENT_INVALID")
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return errors.New("RECEIPT_ENCODING_FAILED")
	}
	temporary, err := os.CreateTemp(parent, ".bundle-verification-*")
	if err != nil {
		return errors.New("OUTPUT_CREATE_FAILED")
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.New("OUTPUT_PERMISSION_FAILED")
	}
	if _, err := temporary.Write(data); err != nil {
		return errors.New("OUTPUT_WRITE_FAILED")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("OUTPUT_SYNC_FAILED")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("OUTPUT_CLOSE_FAILED")
	}
	if err := os.Link(temporaryName, path); err != nil {
		return errors.New("OUTPUT_COMMIT_FAILED")
	}
	if err := os.Remove(temporaryName); err != nil {
		_ = os.Remove(path)
		return errors.New("OUTPUT_COMMIT_FAILED")
	}
	committed = true
	return nil
}

func reason(err error) string {
	if code := verify.Reason(err); code != "INTERNAL_VERIFICATION_ERROR" {
		return code
	}
	message := err.Error()
	allowed := []string{"ARGUMENTS_INVALID", "INPUT_JSON_INVALID", "INPUT_JSON_NOT_CANONICAL", "INPUT_PATH_INVALID", "INPUT_READ_FAILED", "OUTPUT_ALREADY_EXISTS", "OUTPUT_CLOSE_FAILED", "OUTPUT_COMMIT_FAILED", "OUTPUT_CREATE_FAILED", "OUTPUT_PARENT_INVALID", "OUTPUT_PATH_INVALID", "OUTPUT_PERMISSION_FAILED", "OUTPUT_SYNC_FAILED", "OUTPUT_WRITE_FAILED", "RECEIPT_ENCODING_FAILED"}
	sort.Strings(allowed)
	if index := sort.SearchStrings(allowed, message); index < len(allowed) && allowed[index] == message {
		return message
	}
	return "INTERNAL_VERIFICATION_ERROR"
}

func run(ctx context.Context, raw []string) error {
	args, err := parse(raw)
	if err != nil {
		return err
	}
	var request preflight.Request
	var observation preflight.Observation
	if err := canonicalInput(args.request, &request); err != nil {
		return err
	}
	if err := canonicalInput(args.observation, &observation); err != nil {
		return err
	}
	receipt, err := (verify.Verifier{MinimumTrustSequence: minimumTrustSequence}).VerifyBeforeApply(ctx, args.bundleRoot, args.verificationTime, request, observation, nil)
	if err != nil {
		return err
	}
	return atomicReceipt(args.output, receipt)
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, reason(err))
		os.Exit(2)
	}
}
