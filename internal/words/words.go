// Package words splits field and parameter names into words and matches
// them against word lists, in English and Portuguese, whatever the case
// style: userPassword, password_hash, api-token and APIKey all hold a
// credential word. The lists themselves belong to the rules that use them.
package words

import (
	"slices"
	"strings"
	"unicode"
)

// The general describing and reference words, for Matches.
var (
	// Describing words, right after a matched word, mean the field
	// describes the secret instead of holding it: passwordPolicy,
	// tokenExpiresAt, apiKeyId, senhaValidade. Only the next word counts:
	// senhaEmTextoPlano still holds a password.
	Describing = []string{
		"policy", "rules", "type", "format", "url", "uri", "endpoint",
		"expires", "expiry", "expiration", "expired", "length", "count",
		"hint", "required", "set", "changed", "updated", "created", "last",
		"status", "id", "ids", "identifier", "name", "prefix", "suffix",
		"arn", "label", "description", "date", "time",
		"ref", "refs", "reference", "requestor", "risk", "score", "namespace",
		"currency", "scanning", "link", "reset", "public",
		"politica", "regras", "tipo", "validade", "expira", "expiracao", "nome",
	}

	// Reference words, right before a matched word, make it something other
	// than a credential: nextPageToken and syncToken are paging cursors,
	// csrfToken is meant to be handed to the page.
	Reference = []string{
		"page", "next", "previous", "prev", "continuation", "sync", "cursor",
		"pagination", "csrf", "xsrf",
	}
)

// Matches is Match with the general Describing and Reference words.
func Matches(name string, list [][]string) bool {
	return Match(name, list, Describing, Reference)
}

// Match reports whether a field name holds one of the entries of list:
// the entry's words appear whole (or as plurals), the word before them is
// not one of reference (which makes it a reference to something else:
// nextPageToken) and the word after them is not one of describing (which
// makes it a description of it: passwordPolicy).
func Match(name string, list [][]string, describing, reference []string) bool {
	words := Split(name)
	for i := range words {
		for _, entry := range list {
			end := i + len(entry)
			if end > len(words) || !slices.EqualFunc(words[i:end], entry, Same) {
				continue
			}
			if i > 0 && slices.Contains(reference, words[i-1]) {
				continue
			}
			if end < len(words) && slices.Contains(describing, words[end]) {
				continue
			}
			return true
		}
	}
	return false
}

// Same matches a listed word and its plural: tokens, apiKeys, senhas,
// addresses, celulares.
func Same(word, listed string) bool {
	rest, ok := strings.CutPrefix(word, listed) // no word+"s" built on each call
	return ok && (rest == "" || rest == "s" || rest == "es")
}

// OneOf reports whether word is one of list, or the plural of one (see
// Same): admins is one of [admin internal].
func OneOf(word string, list []string) bool {
	return slices.ContainsFunc(list, func(listed string) bool { return Same(word, listed) })
}

// Split splits a field name into lowercase words: userPassword,
// password_hash, api-token, APIKey and senhaUsuario become
// [user password], [password hash], [api token], [api key], [senha usuario].
func Split(name string) []string {
	var words []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			words = append(words, foldAccents(strings.ToLower(string(current))))
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
			// The last capital of an acronym starts the next word (APIKey),
			// unless only an "s" follows: IDs and APIs are plural acronyms.
			acronymEnd := unicode.IsUpper(prev) && unicode.IsUpper(r) &&
				lowerRun(runes[i+1:]) > 1
			if lowerToUpper || acronymEnd || unicode.IsDigit(prev) != unicode.IsDigit(r) {
				flush()
			}
		}
		current = append(current, r)
	}
	flush()
	return words
}

// lowerRun counts the lowercase letters at the start of runes.
func lowerRun(runes []rune) int {
	n := 0
	for n < len(runes) && unicode.IsLower(runes[n]) {
		n++
	}
	return n
}

// accents maps the accented letters of Portuguese to plain ones, so
// permissões and permissoes are the same word.
var accents = strings.NewReplacer(
	"á", "a", "à", "a", "â", "a", "ã", "a",
	"é", "e", "ê", "e", "í", "i",
	"ó", "o", "ô", "o", "õ", "o", "ú", "u", "ü", "u", "ç", "c",
)

func foldAccents(word string) string {
	return accents.Replace(word)
}
