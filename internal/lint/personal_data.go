package lint

import (
	"slices"

	"github.com/EduardoMG12/procyon/internal/words"
)

// What a field's name says about the personal data it holds: PRC006 reports
// personal data a spec returns to anyone, and PRC106 (internal/probe)
// reports values an API really returned, through PersonalDataKind.

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
