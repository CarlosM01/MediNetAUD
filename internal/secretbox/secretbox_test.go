package secretbox

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func testBox(t *testing.T, fill byte) *Box {
	t.Helper()
	b, err := New(bytes.Repeat([]byte{fill}, KeySize))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func TestSealOpenRoundTrip(t *testing.T) {
	b := testBox(t, 1)
	sealed, err := b.Seal([]byte("s3cret"), []byte("lab-service"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, []byte("s3cret")) {
		t.Fatal("sealed value contains the plaintext")
	}
	got, err := b.Open(sealed, []byte("lab-service"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != "s3cret" {
		t.Fatalf("Open = %q, want s3cret", got)
	}
}

func TestSealUsesFreshNonces(t *testing.T) {
	b := testBox(t, 1)
	a, _ := b.Seal([]byte("x"), nil)
	c, _ := b.Seal([]byte("x"), nil)
	if bytes.Equal(a, c) {
		t.Fatal("two seals of the same plaintext are identical")
	}
}

func TestOpenRejects(t *testing.T) {
	b := testBox(t, 1)
	sealed, err := b.Seal([]byte("s3cret"), []byte("lab-service"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1

	tests := []struct {
		name   string
		box    *Box
		sealed []byte
		aad    string
	}{
		{"other client id", b, sealed, "far-service"},
		{"altered ciphertext", b, tampered, "lab-service"},
		{"other key", testBox(t, 2), sealed, "lab-service"},
		{"truncated value", b, sealed[:10], "lab-service"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.box.Open(tt.sealed, []byte(tt.aad)); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("Open err = %v, want ErrDecrypt", err)
			}
		})
	}
}

func TestParseKey(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, KeySize))
	if _, err := ParseKey(good); err != nil {
		t.Fatalf("ParseKey(valid): %v", err)
	}
	for name, s := range map[string]string{
		"not base64": "%%%",
		"too short":  base64.StdEncoding.EncodeToString([]byte("short")),
		"empty":      "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKey(s); err == nil {
				t.Fatal("ParseKey error = nil")
			}
		})
	}
}
