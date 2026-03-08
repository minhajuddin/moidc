package oidc

import (
	"fmt"

	"github.com/pelletier/go-toml/v2"
)

func ParseTOMLClaims(tomlStr string) (map[string]interface{}, error) {
	var raw map[string]interface{}
	if err := toml.Unmarshal([]byte(tomlStr), &raw); err != nil {
		return nil, fmt.Errorf("parsing TOML: %w", err)
	}
	for key, val := range raw {
		if !isScalar(val) {
			return nil, fmt.Errorf("claim %q must be a scalar value (string, number, or boolean)", key)
		}
	}
	return raw, nil
}

func isScalar(v interface{}) bool {
	switch v.(type) {
	case string, int64, float64, bool:
		return true
	default:
		return false
	}
}
