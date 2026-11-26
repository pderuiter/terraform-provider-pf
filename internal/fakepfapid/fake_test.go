package fakepfapid

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
)

func mtlsClient(t *testing.T, s *Server) *http.Client {
	t.Helper()
	cert, err := tls.X509KeyPair(s.ClientCertPEM, s.ClientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(s.CACertPEM)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cert}}}}
}

func put(t *testing.T, c *http.Client, url, body string, hdr map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// HoldPendingConflicts answers exactly n conflicts across anchors and
// tables, then lets the next change through.
func TestHoldPendingConflicts(t *testing.T) {
	s := New("blocked")
	defer s.Close()
	c := mtlsClient(t, s)
	create := map[string]string{"If-None-Match": "*"}

	s.HoldPendingConflicts(2)
	if !s.Pending() {
		t.Fatal("no pending change after HoldPendingConflicts")
	}
	if got := put(t, c, s.URL+"/v1/anchors/a", `{"rules":[]}`, create); got != http.StatusConflict {
		t.Fatalf("anchor put 1: %d, want 409", got)
	}
	if got := put(t, c, s.URL+"/v1/tables/blocked", `{"entries":[]}`, nil); got != http.StatusConflict {
		t.Fatalf("table put: %d, want 409", got)
	}
	if s.Pending() {
		t.Fatal("foreign change still pending after 2 conflicts")
	}
	if s.Conflicts != 2 {
		t.Fatalf("Conflicts = %d, want 2", s.Conflicts)
	}
	if got := put(t, c, s.URL+"/v1/anchors/a", `{"rules":[]}`, create); got != http.StatusAccepted {
		t.Fatalf("anchor put after release: %d, want 202", got)
	}
}

// Without HoldPendingConflicts a pending change never clears by itself.
func TestConflictWithoutRelease(t *testing.T) {
	s := New()
	defer s.Close()
	c := mtlsClient(t, s)
	if got := put(t, c, s.URL+"/v1/anchors/a", `{"rules":[]}`, map[string]string{"If-None-Match": "*"}); got != http.StatusAccepted {
		t.Fatalf("first put: %d, want 202", got)
	}
	if got := put(t, c, s.URL+"/v1/qos", `{"queues":[],"rules":[]}`, nil); got != http.StatusConflict {
		t.Fatalf("qos put while pending: %d, want 409", got)
	}
	if !s.Pending() {
		t.Fatal("own change cleared by a conflict")
	}
}
