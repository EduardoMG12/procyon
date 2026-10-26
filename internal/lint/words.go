package lint

import (
	"slices"

	"github.com/EduardoMG12/procyon/internal/words"
)

// The word lists behind the field-name rules. Each entry is a sequence of
// words as words.Split produces them, so "api key" matches apiKey, api_key,
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
	// the server do: how many items, repeats or retries. words.Split cannot
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

// piiWords name personal data. Words are compared after words.Split, which
// lowercases and drops accents.
var piiWords = [][]string{
	{"email"}, {"e", "mail"}, {"phone"}, {"telephone"}, {"cellphone"},
	{"mobile", "number"}, {"telefone"}, {"celular"},
	{"cpf"}, {"rg"}, {"ssn"}, {"social", "security", "number"},
	{"passport"}, {"passaporte"}, {"national", "id"}, {"national", "identifier"}, {"tax", "id"},
	{"address"}, {"endereco"},
	{"birth", "date"}, {"birthdate"}, {"birthday"}, {"date", "of", "birth"}, {"dob"},
	{"data", "nascimento"}, {"nascimento"},
	{"first", "name"}, {"last", "name"}, {"full", "name"}, {"surname"},
	{"nome", "completo"}, {"sobrenome"},
}

// piiDescribingWords, right after a personal-data word, mean the field is
// about the data, not the data: emailTemplate, emailSettings,
// emailVerifiedAt, addressFormat. On top of the general describingWords.
var piiDescribingWords = append(slices.Clone(describingWords),
	"template", "templates", "settings", "config", "configuration", "verified",
	"verification", "enabled", "notifications", "preferences", "provider",
	"server", "host", "port", "domain",
)

// piiReferenceWords, right before a personal-data word, make it something
// other than a person's data: supportEmail (the company's), walletAddress,
// listenAddress, ipAddress.
var piiReferenceWords = append(slices.Clone(referenceWords),
	"support", "sender", "noreply", "reply", "from", "wallet", "contract",
	"listen", "ip", "mac", "server", "host", "bind", "remote", "local", "web",
)

// matches reports whether the field name holds one of the words in list:
// the word appears whole (or as a plural), the word before it does not make
// it a reference, and the word after it does not make it a description.
func matches(name string, list [][]string) bool {
	return words.Match(name, list, describingWords, referenceWords)
}
