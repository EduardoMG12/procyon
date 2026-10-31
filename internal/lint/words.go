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
		{"private", "key"}, {"chave", "privada"},
	}

	// issuedSecretWords name values a server generates and shows once, in
	// the response that creates or rotates them (a webhook's signing
	// secret, an OAuth app's client secret), and never again.
	issuedSecretWords = [][]string{{"secret"}, {"segredo"}}

	// credentialWords name values an API legitimately hands out once (a
	// login returns a token, creating a key returns the key) but that must
	// never be readable again afterwards.
	credentialWords = [][]string{
		{"token"}, {"apikey"}, {"api", "key"}, {"access", "key"},
	}

	// credentialReferenceWords, right before a credential word, make it
	// something other than a credential, on top of the general
	// words.Reference: an identifier (uniqueToken, idempotencyToken), or a
	// token made for the client to hold (EC2's ClientToken, an idempotency
	// key the client chose; a payment widget's client_token). They do not
	// apply to secretWords: clientSecret is a secret.
	credentialReferenceWords = append(slices.Clone(words.Reference), "unique", "idempotency", "client")

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

	// countOrQueryWords are both lists, what a query parameter is checked
	// against, joined once rather than on every check.
	countOrQueryWords = slices.Concat(countWords, countQueryWords)

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

// The personal data whose values have a shape PRC106 can check, by kind.
var (
	emailWords      = [][]string{{"email"}, {"e", "mail"}}
	phoneWords      = [][]string{{"phone"}, {"telephone"}, {"cellphone"}, {"mobile", "number"}, {"telefone"}, {"celular"}}
	nationalIDWords = [][]string{
		{"cpf"}, {"rg"}, {"ssn"}, {"social", "security", "number"},
		{"passport"}, {"passaporte"}, {"national", "id"}, {"national", "identifier"}, {"tax", "id"},
	}
)

// piiWords name personal data: the kinds above, and the ones with no shape
// to check (an address, a birth date, a name). Words are compared after
// words.Split, which lowercases and drops accents.
var piiWords = slices.Concat(emailWords, phoneWords, nationalIDWords, [][]string{
	{"address"}, {"endereco"},
	{"birth", "date"}, {"birthdate"}, {"birthday"}, {"date", "of", "birth"}, {"dob"},
	{"data", "nascimento"}, {"nascimento"},
	{"first", "name"}, {"last", "name"}, {"full", "name"}, {"surname"},
	{"nome", "completo"}, {"sobrenome"},
})

// The kinds of personal data PersonalDataKind tells, as a finding names
// them.
const (
	Email      = "an e-mail address"
	Phone      = "a phone number"
	NationalID = "a national ID"
)

// PersonalDataKind is the kind of personal data a field's name says it
// holds, by PRC006's lists and exceptions (supportEmail is the company's):
// Email, Phone or NationalID. It is "" for any other name, and for
// personal data with no shape a value could be checked against (an
// address, a birth date), so PRC106 reports a value only when both its
// name and its shape say what it is.
func PersonalDataKind(name string) string {
	for _, kind := range []struct {
		words [][]string
		name  string
	}{{emailWords, Email}, {phoneWords, Phone}, {nationalIDWords, NationalID}} {
		if words.Match(name, kind.words, piiDescribingWords, piiReferenceWords) {
			return kind.name
		}
	}
	return ""
}

// piiDescribingWords, right after a personal-data word, mean the field is
// about the data, not the data: emailTemplate, emailSettings,
// emailVerifiedAt, addressFormat. On top of the general words.Describing.
var piiDescribingWords = append(slices.Clone(words.Describing),
	"template", "templates", "settings", "config", "configuration", "verified",
	"verification", "enabled", "notifications", "preferences", "provider",
	"server", "host", "port", "domain",
)

// piiReferenceWords, right before a personal-data word, make it something
// other than a person's data: supportEmail (the company's), walletAddress,
// listenAddress, ipAddress, repositoryFullName (owner/name),
// softDescriptorPhone (the merchant's, on a card statement).
var piiReferenceWords = append(slices.Clone(words.Reference),
	"support", "sender", "noreply", "reply", "from", "wallet", "contract",
	"listen", "ip", "mac", "server", "host", "bind", "remote", "local", "web",
	"repository", "repo", "descriptor",
)
