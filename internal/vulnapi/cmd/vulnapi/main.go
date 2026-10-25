// Command vulnapi serves the vulnerable notes API (or, with -fixed, its
// fixed twin) for `procyon test`. Never expose it outside a disposable
// container.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/EduardoMG12/procyon/internal/vulnapi"
)

func main() {
	addr := flag.String("addr", ":8080", "address to listen on")
	fixed := flag.Bool("fixed", false, "serve the fixed twin, with none of the planted vulnerabilities")
	healthcheck := flag.Bool("healthcheck", false, "check that the API on -addr answers, then exit (for Docker's HEALTHCHECK)")
	flag.Parse()

	if *healthcheck {
		// -addr may be ":8080" or "127.0.0.1:8080"; only the port matters.
		_, port, err := net.SplitHostPort(*addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "vulnapi: -addr:", err)
			os.Exit(1)
		}
		resp, err := http.Get("http://localhost:" + port + "/health")
		if err != nil {
			fmt.Fprintln(os.Stderr, "vulnapi: not healthy:", err)
			os.Exit(1)
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintln(os.Stderr, "vulnapi: not healthy: /health answered", resp.Status)
			os.Exit(1)
		}
		return
	}

	log.Printf("vulnapi (fixed=%v) listening on %s", *fixed, *addr)
	log.Fatal(http.ListenAndServe(*addr, vulnapi.New(*fixed)))
}
