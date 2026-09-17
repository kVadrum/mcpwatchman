// The same operations done safely. NOTHING here may produce a finding.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"os/exec"

	yaml "gopkg.in/yaml.v3"
)

var allowed = map[string]bool{"report.txt": true, "summary.txt": true}

func runPipeline(target string) error {
	return exec.Command("wc", "-l", target).Run()
}

func fetchRegistry() (*http.Response, error) {
	return http.Get("https://registry.modelcontextprotocol.io/v0/servers")
}

type state struct {
	Name string `json:"name"`
}

func loadState(r io.Reader) (state, error) {
	var v state
	b, err := io.ReadAll(r)
	if err != nil {
		return v, err
	}
	return v, json.Unmarshal(b, &v)
}

func readDoc(root, name string) ([]byte, error) {
	if !allowed[name] {
		return nil, errors.New("denied")
	}
	return os.ReadFile(filepath.Join(root, "report.txt"))
}

func handleCountTool(ctx context.Context, req string) (string, error) {
	if !allowed[req] {
		return "", errors.New("denied")
	}
	out, err := exec.Command("wc", "-l", req).Output()
	return string(out), err
}

type config struct {
	Name string `yaml:"name"`
}

func loadConfig(b []byte) (config, error) {
	var v config
	return v, yaml.Unmarshal(b, &v)
}
