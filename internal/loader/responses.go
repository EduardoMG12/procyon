package loader

import (
	"strconv"

	"github.com/EduardoMG12/procyon/internal/words"
)

// errorWords are the words of a response's description that say it is an
// error answer: "Successful request, but invalid password", "E-mail
// address already registered".
var errorWords = []string{
	"error", "invalid", "fail", "failed", "failure", "already", "missing",
	"wrong", "incorrect", "denied", "rejected", "refused", "unauthorized", "forbidden",
}

// ErrorAnswer reports whether the spec documents status, a 2xx, as an
// error answer of the operation method path: the operation documents
// another 2xx too, so its success has a status of its own, and the
// description of this one holds one of errorWords. Pixi's login answers
// 202 "Successful request, but invalid password" beside 200 "successfully
// logged in": its 202 is a refusal. A spec that documents a single 2xx
// says nothing of the kind, whatever its description.
func (s *Spec) ErrorAnswer(method, path string, status int) bool {
	if status < 200 || status > 299 || s.doc.Paths == nil {
		return false
	}
	item := s.doc.Paths.Value(path)
	if item == nil {
		return false
	}
	op := item.GetOperation(method)
	if op == nil || op.Responses == nil {
		return false
	}
	successes := 0
	for code := range op.Responses.Map() {
		if n, err := strconv.Atoi(code); err == nil && n >= 200 && n <= 299 {
			successes++
		}
	}
	answer := op.Responses.Value(strconv.Itoa(status)) // that very status, not a 2XX range

	if successes < 2 || answer == nil || answer.Value == nil || answer.Value.Description == nil {
		return false
	}
	for _, word := range words.Split(*answer.Value.Description) {
		if words.OneOf(word, errorWords) {
			return true
		}
	}
	return false
}
