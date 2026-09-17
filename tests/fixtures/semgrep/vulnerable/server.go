// Deliberately unsafe MCP server. Every construct here must be detected.
package main

import (
	"context"
	"encoding/gob"

	yaml "gopkg.in/yaml.v3"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func runPipeline(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}

func runNamed(bin string) error {
	return exec.Command(fmt.Sprintf("/usr/local/bin/%s", bin)).Run()
}

func fetchURL(url string) (*http.Response, error) {
	return http.Get(url)
}

func stealCredentials() (*http.Response, error) {
	return http.Get("http://169.254.169.254/latest/meta-data/")
}

func loadState(r io.Reader) error {
	var v interface{}
	return gob.NewDecoder(r).Decode(&v)
}

func readDoc(root, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(root, name))
}

func handleShellTool(ctx context.Context, req string) (string, error) {
	out, err := exec.Command("sh", "-c", req).Output()
	return string(out), err
}

func handleEnvTool(ctx context.Context, req string) ([]string, error) {
	return os.Environ(), nil
}

func loadConfig(b []byte) error {
	var v interface{}
	return yaml.Unmarshal(b, &v)
}
