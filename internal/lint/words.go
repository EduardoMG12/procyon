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

	// describingWords, right after a matched word, mean the field
	// describes the secret instead of holding it: passwordPolicy,
	// tokenExpiresAt, apiKeyId, senhaValidade. Only the next word counts:
	// senhaEmTextoPlano still holds a password.
	describingWords = []string{
		"policy", "rules", "type", "format", "url", "uri", "endpoint",
		"expires", "expiry", "expiration", "expired", "length", "count",
		"hint", "required", "set", "changed", "updated", "created", "last",
		"status", "id", "ids", "identifier", "name", "prefix", "suffix",
		"arn", "label", "description", "date", "time",
		"ref", "refs", "reference", "requestor", "risk", "score", "namespace",
		"currency", "scanning", "link", "reset", "public",
		"politica", "regras", "tipo", "validade", "expira", "expiracao", "nome",
	}

	// referenceWords, right before a matched word, make it something other
	// than a credential: nextPageToken and syncToken are paging cursors,
	// csrfToken is meant to be handed to the page.
	referenceWords = []string{
		"page", "next", "previous", "prev", "continuation", "sync", "cursor",
		"pagination", "csrf", "xsrf",
	}

	// credentialParameterWords name a parameter that carries the caller's
	// credential, when a spec sends it as a parameter rather than through a
	// security scheme.
	credentialParameterWords = [][]string{
		{"authorization"}, {"access", "token"}, {"auth", "token"},
		{"session", "token"}, {"apikey"}, {"api", "key"}, {"access", "key"},
	}

	// countWords name numbers that set how much work one request makes
	// the server do: how many items, repeats or retries. splitWords cannot
	// split an all-lowercase name, so pagesize and perpage are listed too.
	countWords = [][]string{
		{"limit"}, {"count"}, {"repeat"}, {"retry"}, {"retries"}, {"attempt"},
		{"iteration"}, {"per", "page"}, {"perpage"}, {"page", "size"},
		{"pagesize"}, {"batch", "size"}, {"batchsize"}, {"max", "results"},
		{"maxresults"},
		{"limite"}, {"repeticao"}, {"repeticoes"}, {"tentativa"},
		{"por", "pagina"}, {"tamanho", "pagina"},
	}

	// countQueryWords are count words only in a query parameter (?top=,
	// ?size=); in a body they are usually something else (marginTop,
	// waterDepth, shoe size).
	countQueryWords = [][]string{{"top"}, {"take"}, {"depth"}, {"size"}}

	// countDescribingWords, right after a count word, make the field a
	// value rather than an amount of work: limitPrice, retryAfter,
	// repeatEvery, depthMeters.
	countDescribingWords = []string{
		"price", "amount", "value", "date", "time", "type", "id", "order", "reached",
		"after", "every", "interval", "delay", "seconds", "minutes", "meters", "speed",
		"preco", "valor", "data", "tipo", "intervalo", "metros",
	}

	// countReferenceWords, right before a count word, make it a stored
	// value: creditLimit, rateLimit, stockCount, viewCount, marginTop.
	countReferenceWords = []string{
		"credit", "spending", "spend", "overdraft", "budget", "rate", "margin",
		"padding", "stock", "view", "like", "follower", "bit", "color", "water",
		"credito", "gasto", "estoque",
	}
)

// matches reports whether the field name holds one of the words in list:
// the word appears whole (or as a plural), the word before it does not make
// it a reference, and the word after it does not make it a description.
func matches(name string, list [][]string) bool {
	return matchesWith(name, list, describingWords, referenceWords)
}

// matchesWith is matches with the describing and reference words given.
func matchesWith(name string, list [][]string, describing, reference []string) bool {
	words := splitWords(name)
	for i := range words {
		for _, entry := range list {
			end := i + len(entry)
			if end > len(words) || !slices.EqualFunc(words[i:end], entry, sameWord) {
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

// sameWord matches a listed word and its plural: tokens, apiKeys, senhas,
// addresses, celulares.
func sameWord(word, listed string) bool {
	rest, ok := strings.CutPrefix(word, listed) // no word+"s" built on each call
	return ok && (rest == "" || rest == "s" || rest == "es")
}

// splitWords splits a field name into lowercase words: userPassword,
// password_hash, api-token, APIKey and senhaUsuario become
// [user password], [password hash], [api token], [api key], [senha usuario].
func splitWords(name string) []string {
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
