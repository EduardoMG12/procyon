package probe

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/EduardoMG12/procyon/internal/vulnapi"
)

func TestInternalError(t *testing.T) {
	tests := []struct {
		name, body string
		want       string // what it is; "" when nothing is found
		line       string // where the evidence starts
	}{
		{"PHP uncaught", "PHP Fatal error:  Uncaught Exception: boom in /var/www/api.php:12\nStack trace:\n#0 {main}",
			"a PHP error", "Fatal error:  Uncaught Exception: boom in /var/www/api.php:12"},
		{"PHP in HTML", "<br />\n<b>Fatal error</b>:  Call to undefined function f() in <b>/var/www/api.php</b> on line <b>7</b><br />",
			"a PHP error", "Fatal error</b>:  Call to undefined function f() in <b>/var/www/api.php</b> on line <b>7</b><br />"},
		{"PHP stack trace", "Exception: boom\nStack trace:\n#0 /var/www/db.php(3): query()", "a PHP error", "Stack trace:"},
		{"Python, in JSON", `{"detail":"Traceback (most recent call last):\n  File \"/app/main.py\", line 3"}`,
			"a Python stack trace", "Traceback (most recent call last):"},
		{"Java thread", "Exception in thread \"main\" java.lang.NullPointerException", "a Java stack trace",
			"Exception in thread \"main\" java.lang.NullPointerException"},
		{"Java frame, in JSON", `{"trace":"IllegalStateException\n\n\tat org.springframework.web.Servlet.service(Servlet.java:12)"}`,
			"a Java stack trace", `at org.springframework.web.Servlet.service(Servlet.java:12)"}`},
		{"Node", "TypeError: x is undefined\n    at Object.<anonymous> (/app/index.js:3:15)", "a Node.js stack trace",
			"at Object.<anonymous> (/app/index.js:3:15)"},
		{"Node, a handler's frame", "Error: boom\n    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)",
			"a Node.js stack trace", "at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)"},
		{"Node, escaped by Go's JSON", `{"stack":"at Object.\u003canonymous\u003e (/app/index.js:3:15)"}`, "a Node.js stack trace",
			`at Object.<anonymous> (/app/index.js:3:15)"}`},
		{"Java, a JDK frame", "java.lang.NullPointerException\n\tat java.base/java.util.Objects.requireNonNull(Objects.java:209)",
			"a Java stack trace", "at java.base/java.util.Objects.requireNonNull(Objects.java:209)"},
		{".NET, System.Exception", "System.Exception: boom", "a .NET stack trace", "System.Exception: boom"},
		{"PHP, Windows line breaks, in JSON", `{"e":"Stack trace:\r\n#0 C:\\app\\db.php(3): query()"}`, "a PHP error", "Stack trace:"},
		{"Go", "panic: runtime error: invalid memory address\n\ngoroutine 7 [running]:\nmain.handler()", "a Go panic",
			"panic: runtime error: invalid memory address"},
		{".NET", "System.NullReferenceException: Object reference not set to an instance of an object.", "a .NET stack trace",
			"System.NullReferenceException: Object reference not set to an instance of an object."},
		{".NET frame", `   at Api.Program.Main() in C:\src\Program.cs:line 5`, "a .NET stack trace", `at Api.Program.Main() in C:\src\Program.cs:line 5`},
		{"Ruby", "app/controllers/notes_controller.rb:12:in `show'", "a Ruby stack trace", "app/controllers/notes_controller.rb:12:in `show'"},
		{"MySQL", `{"error":"SQLSTATE[42000]: Syntax error: 1064 You have an error in your SQL syntax"}`, "a database error",
			`SQLSTATE[42000]: Syntax error: 1064 You have an error in your SQL syntax"}`},
		{"PostgreSQL", `ERROR:  syntax error at or near "WHERE"`, "a database error", `syntax error at or near "WHERE"`},
		{"Oracle", "ORA-00933: SQL command not properly ended", "a database error", "ORA-00933: SQL command not properly ended"},
		{"SQLite", "SQLite Error 1: 'no such table: notes'.", "a database error", "SQLite Error 1: 'no such table: notes'."},

		{"a plain JSON error", `{"error":"title is required"}`, "", ""},
		{"a request ID called trace", `{"error":"not found","trace":"req-7f3a9c2e"}`, "", ""},
		{"exception in prose", `{"message":"An exception occurred while saving the note; please try again"}`, "", ""},
		{"panic in prose", `{"message":"Don't panic: your note is saved"}`, "", ""},
		{"a title about stack traces", `{"title":"Stack trace: how to read one"}`, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			what, line := internalError([]byte(tt.body))
			if what != tt.want || line != tt.line {
				t.Errorf("internalError = %q, %q; want %q, %q", what, line, tt.want, tt.line)
			}
		})
	}
}

// An API that answers everything with a trace is reported once per
// operation, and the token it echoes is masked in the evidence. With
// --base-spec, discovery still reads the unchanged operations, for IDs,
// but only the changed ones are reported.
func TestPRC109OncePerOperation(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Traceback (most recent call last): " + r.Header.Get("Authorization") + "\n  File \"/app/main.py\""))
	})
	tests := []struct {
		baseSpec string
		want     []string
	}{
		// What A's discovery, the anonymous calls and the malformed pass
		// reach; the answers hold no IDs, so nothing with one in its path
		// or query is called.
		{"", []string{"GET /health", "GET /me", "GET /notes", "POST /notes", "GET /shop", "GET /menu", "GET /orders", "POST /reviews"}},
		{"../../testdata/specs/runtime-notes-base.yaml", []string{"GET /health", "POST /notes"}},
	}
	for _, tt := range tests {
		rep := runOn(t, vulnapiSpec, handler, Options{BaseSpec: tt.baseSpec})
		var operations []string
		for _, f := range findingsOf(rep, "PRC109") {
			operations = append(operations, f.Operation)
			if len(f.Evidence) != 1 || strings.Contains(f.Evidence[0].Body, vulnapi.TokenA) || strings.Contains(f.Evidence[0].Body, vulnapi.TokenB) ||
				!strings.HasPrefix(f.Evidence[0].Body, "Traceback (most recent call last):") {
				t.Errorf("%s: evidence %+v, want one exchange with the trace's line and no token", f.Operation, f.Evidence)
			}
		}
		if !slices.Equal(operations, tt.want) {
			t.Errorf("base spec %q: PRC109 on %q, want %q", tt.baseSpec, operations, tt.want)
		}
	}
}
