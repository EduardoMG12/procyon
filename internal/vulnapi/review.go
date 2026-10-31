package vulnapi

import (
	"encoding/json"
	"net/http"
)

// maxComment is the spec's maxLength for a review's comment.
const maxComment = 500

// debugTrace is what a framework left in debug mode adds to an error: the
// stack trace of what failed, with the server's file paths. It is made up,
// the same every time.
const debugTrace = "Traceback (most recent call last):\n" +
	"  File \"/srv/app/reviews.py\", line 14, in create\n" +
	"    rating = int(body[\"rating\"])\n" +
	"ValueError: invalid literal for int() with base 10"

// review takes a rating of the app from 1 to 5, with a comment.
//
// Vulnerable (PRC109): a body that is not a valid review is refused with
// a 400, as it should be, but the answer holds a stack trace.
func (s *server) review(w http.ResponseWriter, r *http.Request) {
	if _, ok := authenticated(w, r); !ok {
		return
	}
	var in struct {
		Rating  *int   `json:"rating"`
		Comment string `json:"comment"`
	}
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in)
	if err != nil || in.Rating == nil || *in.Rating < 1 || *in.Rating > 5 || len(in.Comment) > maxComment {
		answer := map[string]string{"error": "rating must be a whole number from 1 to 5; comment at most 500 characters"}
		if !s.fixed {
			answer["debug"] = debugTrace
		}
		writeJSON(w, http.StatusBadRequest, answer)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
