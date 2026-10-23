package lint

import (
	"slices"
	"strings"
	"unicode"
)

// The word lists behind the field-name rules. Each entry is a sequence of
// words as splitWords produces them, so "api key" matches apiKey, api_key,
// api-key and APIKey. English and Portuguese.
//
// Changing a list changes what Procyon reports on every spec: add a fixture
// that proves the new word (and one that proves what it must not match), and
// report the corpus difference in the PR.
var (
	// secretWords name values that must never appear in a response.
	secretWords = [][]string{
		{"password"}, {"passwd"}, {"passphrase"}, {"senha"},
		{"secret"}, {"segredo"},
		{"private", "key"}, {"chave", "privada"},
	}

	// credentialWords name values an API legitimately hands out once (a
	// login returns a token, creating a key returns the key) but that must
	// never be readable again afterwards.
	credentialWords = [][]string{
		{"token"}, {"apikey"}, {"api", "key"}, {"access", "key"},
	}

	// metadataWords, after a matched word, mean the field describes the
	// secret rather than holding it: passwordPolicy, tokenExpiresAt,
	// tokenType, senhaValidade.
	metadataWords = []string{
		"policy", "rules", "type", "format", "url", "uri", "endpoint",
		"expires", "expiry", "expiration", "expired", "at", "date", "time",
		"length", "count", "hint", "required", "set", "changed", "updated",
		"created", "last", "status",
		"politica", "regras", "tipo", "validade", "expira", "expiracao", "em", "data",
	}
)

// matches reports whether the field name holds one of the words in list:
// the word appears whole, and no metadata word follows it.
func matches(name string, list [][]string) bool {
	words := splitWords(name)
	for i := range words {
		for _, entry := range list {
			end := i + len(entry)
			if end > len(words) || !slices.Equal(words[i:end], entry) {
				continue
			}
			if !slices.ContainsFunc(words[end:], func(w string) bool { return slices.Contains(metadataWords, w) }) {
				return true
			}
		}
	}
	return false
}

// splitWords splits a field name into lowercase words: userPassword,
// password_hash, api-token, APIKey and senhaUsuario become
// [user password], [password hash], [api token], [api key], [senha usuario].
func splitWords(name string) []string {
	var words []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			words = append(words, strings.ToLower(string(current)))
			current = current[:0]
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush() // _, -, ., spaces
			continue
		}
		if i > 0 && len(current) > 0 {
			prev := runes[i-1]
			lowerToUpper := unicode.IsLower(prev) && unicode.IsUpper(r)
			// The last capital of an acronym starts the next word: APIKey.
			acronymEnd := unicode.IsUpper(prev) && unicode.IsUpper(r) &&
				i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if lowerToUpper || acronymEnd || unicode.IsDigit(prev) != unicode.IsDigit(r) {
				flush()
			}
		}
		current = append(current, r)
	}
	flush()
	return words
}
