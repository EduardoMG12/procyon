package probe

import (
	"fmt"
	"strings"
	"testing"
)

// A 1 MiB-ish answer: the size maxResponse lets through.
func bigList(prefix string, n int) []byte {
	var b strings.Builder
	b.WriteString("[")
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"id": "%s-%d", "owner": "%s"}`, prefix, i, prefix)
	}
	b.WriteString("]")
	return []byte(b.String())
}

func BenchmarkSharedUnseen(b *testing.B) {
	toA, toB := bigList("a", 20000), bigList("a", 20000)
	ofB := newHarvest(nil)
	ofB.add("/list", bigList("b", 20000))
	b.ResetTimer()
	for range b.N {
		sharedUnseen(toB, toA, ofB, nil)
	}
}
