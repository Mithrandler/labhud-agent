// Package config reads the agent's settings and keeps its identity.
//
// Settings come from <dir>/config (KEY=VALUE lines, written by install.sh) and the environment,
// which wins (the Docker image). The identity — the agent id, its key and labhud's certificate
// pin — is written to <dir>/key (mode 600) at pairing and never leaves the host.
package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const DefaultDir = "/etc/labhud-agent"

type Config struct {
	Dir      string  // LABHUD_AGENT_DIR
	URL      string  // LABHUD_URL: http(s)://labhud:8095
	Code     string  // LABHUD_AGENT_CODE: the one-time pairing code, used once
	Name     string  // LABHUD_AGENT_NAME: the name in ⚙ (the host name when empty)
	Root     string  // LABHUD_AGENT_ROOT: where the host's /proc, /sys and / are ("/host" in a container)
	BaseW    float64 // LABHUD_AGENT_BASE_W: watts added to the power estimate
	PriceKWh float64 // LABHUD_AGENT_PRICE_KWH
	PVEURL   string  // LABHUD_PVE_URL (https://localhost:8006)
	PVEToken string  // LABHUD_PVE_TOKEN: user@realm!name=uuid, made by install.sh
	PteroURL string  // LABHUD_PTERO_URL: the panel
	PteroKey string  // LABHUD_PTERO_KEY: a client API key
	PteroPin string  // LABHUD_PTERO_PIN: SHA-256 of the panel's certificate, for a self-signed one
	Releases string  // LABHUD_AGENT_RELEASES: where updates come from (selfupdate.Releases when empty)
	// LABHUD_AGENT_AUTO_LABELS: "k=v,k2=v2", labels a container gets when it is made again while
	// labhud updates it on its own (and loses when it no longer does), e.g. dockhand.update=false
	// so that another updater leaves it alone
	AutoLabels map[string]string
}

// labels reads "k=v,k2=v2".
func labels(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.TrimSpace(k) != "" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// InContainer: the image is the agent (LABHUD_AGENT_ROOT points at the host, or Docker's marker).
func (c Config) InContainer() bool {
	if c.Root != "" && c.Root != "/" {
		return true
	}
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

// Load reads <dir>/config if it exists, then the environment.
func Load(dir string) (Config, error) {
	if d := os.Getenv("LABHUD_AGENT_DIR"); d != "" {
		dir = d
	}
	if dir == "" {
		dir = DefaultDir
	}
	vals := map[string]string{}
	f, err := os.Open(filepath.Join(dir, "config"))
	if err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
				v = v[1 : len(v)-1]
			}
			vals[strings.TrimSpace(k)] = v
		}
		f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}
	get := func(k, def string) string {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			return v
		}
		if v, ok := vals[k]; ok && v != "" {
			return v
		}
		return def
	}
	num := func(k string) float64 {
		n, _ := strconv.ParseFloat(get(k, "0"), 64)
		return n
	}
	return Config{
		Dir: dir, URL: strings.TrimRight(get("LABHUD_URL", ""), "/"), Code: get("LABHUD_AGENT_CODE", ""),
		Name: get("LABHUD_AGENT_NAME", ""), Root: get("LABHUD_AGENT_ROOT", "/"),
		BaseW: num("LABHUD_AGENT_BASE_W"), PriceKWh: num("LABHUD_AGENT_PRICE_KWH"),
		PVEURL: get("LABHUD_PVE_URL", "https://localhost:8006"), PVEToken: get("LABHUD_PVE_TOKEN", ""),
		PteroURL: strings.TrimRight(get("LABHUD_PTERO_URL", ""), "/"), PteroKey: get("LABHUD_PTERO_KEY", ""),
		PteroPin: strings.ToLower(strings.ReplaceAll(get("LABHUD_PTERO_PIN", ""), ":", "")),
		Releases: get("LABHUD_AGENT_RELEASES", ""), AutoLabels: labels(get("LABHUD_AGENT_AUTO_LABELS", "")),
	}, nil
}

// Identity is what pairing leaves behind.
type Identity struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	TLSFP string `json:"tls_fp,omitempty"`
	URL   string `json:"url"` // the labhud it was paired with: another URL needs a new pairing
}

func keyPath(dir string) string { return filepath.Join(dir, "key") }

// LoadIdentity gives nil (and no error) when the agent was never paired.
func LoadIdentity(dir string) (*Identity, error) {
	b, err := os.ReadFile(keyPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil || id.ID == "" || id.Key == "" {
		return nil, errors.New(keyPath(dir) + " is damaged: delete it and pair again")
	}
	return &id, nil
}

// Save writes the identity atomically, readable by root only.
func (id *Identity) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(id)
	tmp := keyPath(dir) + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, keyPath(dir))
}

// Forget deletes the identity (the agent was removed in labhud).
func Forget(dir string) error {
	err := os.Remove(keyPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
