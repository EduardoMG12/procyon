package loader

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/EduardoMG12/procyon/internal/report"

	"github.com/getkin/kin-openapi/openapi3"
)

// invalidSpec is the input error for a spec kin-openapi's validation
// refuses. kin-openapi joins its errors on one line with " | " and gives no
// line numbers; here each error gets its own line, starting with its place
// in the original file when kin-openapi recorded one. A single error stays
// on one line. hint, when not empty, follows "invalid spec".
func invalidSpec(path string, err error, hint string, asGiven func(report.Location) report.Location) error {
	errs := []error{err}
	if multi, ok := err.(openapi3.MultiError); ok {
		errs = multi
	}
	if len(errs) == 1 {
		where := path
		if loc := asGiven(Locate(errorOrigin(err))); loc.Line > 0 {
			where = fmt.Sprintf("%s:%d:%d", loc.File, loc.Line, loc.Column)
		}
		return fmt.Errorf("%s: invalid spec%s: %s", where, hint, firstLine(err))
	}
	lines := make([]string, len(errs))
	for i, e := range errs {
		lines[i] = firstLine(e)
		if loc := asGiven(Locate(errorOrigin(e))); loc.Line > 0 {
			lines[i] = fmt.Sprintf("%s:%d:%d: %s", loc.File, loc.Line, loc.Column, lines[i])
		}
	}
	return fmt.Errorf("%s: invalid spec%s, %d errors:\n  %s", path, hint, len(errs), strings.Join(lines, "\n  "))
}

// firstLine is what an error says is wrong: some validation errors append
// the schema and value on extra lines.
func firstLine(err error) string {
	line, _, _ := strings.Cut(err.Error(), "\n")
	return line
}

// errorOrigin returns where in the spec kin-openapi says a validation error
// is, or nil. About thirty of kin-openapi's error types carry the place in
// an Origin field, and they share no method to ask for it, so the field is
// found by its name, on the error and on each error it wraps.
func errorOrigin(err error) *openapi3.Origin {
	for ; err != nil; err = errors.Unwrap(err) {
		v := reflect.ValueOf(err)
		if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
			continue
		}
		if field := v.Elem().FieldByName("Origin"); field.IsValid() {
			if origin, ok := field.Interface().(*openapi3.Origin); ok && origin != nil {
				return origin
			}
		}
	}
	return nil
}
