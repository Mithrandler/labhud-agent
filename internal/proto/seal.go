package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// Sealed values: a registry's login inside a command. A frame is signed, not encrypted, and
// labhud may speak plain ws://, so the secret travels XORed with a keystream only the holders of
// the agent's key can make, bound to the connection, the command and a fresh nonce:
//
//	k        = HMAC(key, "V|seal|<session>|<cmd>|<nonce>")
//	stream_i = HMAC(k, "V|seal-stream|<i>")   (raw 32 bytes, i = 0, 1, 2 …)
//	box      = hex(text XOR stream_0 || stream_1 || …)
//
// The frame's signature covers the box, so it cannot be changed unseen. labhud's agentproto.py
// does the same; the vectors pin it.

// MaxSealed bounds a sealed text, in bytes.
const MaxSealed = 4096

func keystream(key, session, cmd, nonce string, n int) []byte {
	k := []byte(mac(key, V+"|seal|"+session+"|"+cmd+"|"+nonce))
	out := make([]byte, 0, n+sha256.Size)
	for i := 0; len(out) < n; i++ {
		h := hmac.New(sha256.New, k)
		h.Write([]byte(V + "|seal-stream|" + strconv.Itoa(i)))
		out = h.Sum(out)
	}
	return out[:n]
}

func xor(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// Seal is labhud's side, here for the tests.
func Seal(key, session, cmd, nonce, text string) (string, error) {
	if len(text) > MaxSealed {
		return "", errors.New("too long to seal")
	}
	if !hex16.MatchString(nonce) {
		return "", errors.New("the nonce is 16 bytes of hex")
	}
	return hex.EncodeToString(xor([]byte(text), keystream(key, session, cmd, nonce, len(text)))), nil
}

// Unseal gives a sealed text back.
func Unseal(key, session, cmd, nonce, box string) (string, error) {
	if !hex16.MatchString(nonce) || len(box) > 2*MaxSealed || strings.ToLower(box) != box {
		return "", errors.New("not a sealed value")
	}
	raw, err := hex.DecodeString(box)
	if err != nil {
		return "", errors.New("not a sealed value")
	}
	return string(xor(raw, keystream(key, session, cmd, nonce, len(raw)))), nil
}

// DockerHub is the registry of an image named without one ("nginx", "linuxserver/sonarr").
const DockerHub = "docker.io"

// RegistryOf is the registry an image reference is pulled from, as Docker reads it: the part
// before the first "/" when it has a "." or a ":" or is "localhost", else Docker Hub. Lower case;
// "" for an image id or anything that is not a name. labhud's agentproto.registry_of is the same.
func RegistryOf(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "sha256:") || hex32.MatchString(ref) || strings.ContainsAny(ref, " \t\r\n\v\f") {
		return ""
	}
	host := DockerHub
	if first, _, ok := strings.Cut(ref, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		host = strings.ToLower(first)
	}
	switch host {
	case "index.docker.io", "registry-1.docker.io":
		host = DockerHub
	}
	return host
}
