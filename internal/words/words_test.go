package words

import (
	"slices"
	"testing"
)

func TestSplit(t *testing.T) {
	tests := map[string][]string{
		"userPassword":  {"user", "password"},
		"password_hash": {"password", "hash"},
		"api-token":     {"api", "token"},
		"APIKey":        {"api", "key"},
		"userIDs":       {"user", "ids"},
		"senhaUsuário":  {"senha", "usuario"},
		"v2Token":       {"v", "2", "token"},
	}
	for name, want := range tests {
		if got := Split(name); !slices.Equal(got, want) {
			t.Errorf("Split(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestMatch(t *testing.T) {
	list := [][]string{{"password"}, {"api", "key"}}
	describing, reference := []string{"policy"}, []string{"next"}
	tests := map[string]bool{
		"userPassword":       true,
		"apiKeys":            true, // a plural
		"passwordPolicy":     false, // describes the password
		"nextPassword":       false, // refers to another one
		"passwordsAreStored": true,
		"keyApi":             false, // words in the wrong order
	}
	for name, want := range tests {
		if got := Match(name, list, describing, reference); got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
}
