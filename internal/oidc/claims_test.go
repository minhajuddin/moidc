package oidc

import "testing"

func TestParseTOMLClaims(t *testing.T) {
	toml := `name = "Jane Doe"
age = 30
active = true
score = 9.5
`
	claims, err := ParseTOMLClaims(toml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims["name"] != "Jane Doe" {
		t.Errorf("expected name='Jane Doe', got %v", claims["name"])
	}
	if claims["age"] != int64(30) {
		t.Errorf("expected age=30, got %v", claims["age"])
	}
	if claims["active"] != true {
		t.Errorf("expected active=true, got %v", claims["active"])
	}
}

func TestParseTOMLClaims_RejectsNested(t *testing.T) {
	toml := `[address]
city = "NYC"
`
	_, err := ParseTOMLClaims(toml)
	if err == nil {
		t.Fatal("expected error for nested TOML, got nil")
	}
}
