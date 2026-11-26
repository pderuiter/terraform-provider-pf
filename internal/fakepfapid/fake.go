// Package fakepfapid is an in-memory pfapid for tests: mutual TLS, ETags,
// one pending change at a time, confirm and rollback, drift. It does not
// validate rules beyond a few markers the tests use.
package fakepfapid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"time"
)

// RejectLabel: a rule with this label is refused by "pfctl" (422).
const RejectLabel = "pfctl-rejects-this"

type change struct {
	id, actor, kind, name, op string
	prevA, nextA              json.RawMessage // anchor rules; nil = absent
	prevT, nextT              []string
	prevQ, nextQ              json.RawMessage
	etag                      string
}

type Server struct {
	*httptest.Server
	CACertPEM, ClientCertPEM, ClientKeyPEM []byte

	mu      sync.Mutex
	anchors map[string]json.RawMessage // committed rules
	tables  map[string][]string        // committed entries
	kernelA map[string]json.RawMessage // what "pf" has loaded
	kernelT map[string][]string
	qos     json.RawMessage // committed QoS document
	kernelQ json.RawMessage
	pending *change
	seq     int
	// releaseAfter > 0: the pending foreign change clears after answering
	// that many more conflicts (HoldPendingConflicts).
	releaseAfter int
	// Counters and switches for tests.
	Confirms, Rollbacks, Conflicts int
	FailConfirm                    bool
}

func etag(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:16])
}

// New starts a TLS 1.3 server that requires a client certificate signed by
// its own CA. Managed tables are those named.
func New(tables ...string) *Server {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(cn string, serial int64, eku x509.ExtKeyUsage) ([]byte, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{eku}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
		kd, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	}
	srvCert, srvKey := issue("pfapid", 2, x509.ExtKeyUsageServerAuth)
	cliCert, cliKey := issue("tf-test", 3, x509.ExtKeyUsageClientAuth)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	tc, _ := tls.X509KeyPair(srvCert, srvKey)

	s := &Server{
		CACertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		ClientCertPEM: cliCert, ClientKeyPEM: cliKey,
		anchors: map[string]json.RawMessage{}, tables: map[string][]string{},
		kernelA: map[string]json.RawMessage{}, kernelT: map[string][]string{},
		qos: json.RawMessage(`{"queues":[],"rules":[]}`), kernelQ: json.RawMessage(`{"queues":[],"rules":[]}`),
	}
	for _, t := range tables {
		s.tables[t] = []string{}
		s.kernelT[t] = []string{}
	}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{tc},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	s.StartTLS()
	return s
}

// TamperAnchor changes what the "kernel" has loaded, to simulate drift.
func (s *Server) TamperAnchor(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kernelA[name] = json.RawMessage(`[{"tampered":true}]`)
}

func (s *Server) TamperTable(name, entry string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kernelT[name] = append(slices.Clone(s.kernelT[name]), entry)
}

// Anchor returns the committed rules JSON of an anchor (nil if absent).
func (s *Server) Anchor(name string) json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.anchors[name]
}

func (s *Server) Table(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.tables[name])
}

func (s *Server) Pending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending != nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, c, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]string{"code": c, "message": msg}})
}

func ifMatch(r *http.Request) string { return strings.Trim(r.Header.Get("If-Match"), `"`) }

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	actor := r.TLS.PeerCertificates[0].Subject.CommonName
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/healthz":
		writeJSON(w, 200, map[string]string{"status": "ok", "client": actor})
	case parts[0] == "anchors" && len(parts) == 2:
		s.anchor(w, r, actor, parts[1])
	case parts[0] == "anchors" && len(parts) == 3 && parts[2] == "validate" && r.Method == http.MethodPost:
		var b struct {
			Rules []map[string]any `json:"rules"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			fail(w, 400, "invalid", "bad body")
			return
		}
		var out []string
		for _, rl := range b.Rules {
			if rl["label"] == RejectLabel {
				fail(w, 422, "pf_rejected", "syntax error")
				return
			}
			out = append(out, fmt.Sprintf("%v %v on %v %v", rl["action"], rl["direction"], rl["interface"], rl["family"]))
		}
		writeJSON(w, 200, map[string]any{"rendered": out, "normalised": out})
	case parts[0] == "anchors" && len(parts) == 3 && parts[2] == "drift":
		want, ok := s.anchors[parts[1]]
		if !ok {
			fail(w, 404, "not_found", "anchor")
			return
		}
		in := string(s.kernelA[parts[1]]) == string(want)
		writeJSON(w, 200, map[string]any{"in_sync": in, "expected": []string{string(want)}, "live": []string{string(s.kernelA[parts[1]])}})
	case parts[0] == "tables" && len(parts) == 2:
		s.table(w, r, actor, parts[1])
	case parts[0] == "tables" && len(parts) == 3 && parts[2] == "drift":
		want, ok := s.tables[parts[1]]
		if !ok {
			fail(w, 404, "not_found", "table")
			return
		}
		a, b := slices.Sorted(slices.Values(want)), slices.Sorted(slices.Values(s.kernelT[parts[1]]))
		writeJSON(w, 200, map[string]any{"in_sync": slices.Equal(a, b), "expected": a, "live": b})
	case parts[0] == "qos" && len(parts) == 1:
		s.qosDoc(w, r, actor)
	case parts[0] == "qos" && len(parts) == 2 && parts[1] == "validate" && r.Method == http.MethodPost:
		doc, ok := s.readQoS(w, r)
		if !ok {
			return
		}
		var q struct {
			Queues []map[string]any `json:"queues"`
			Rules  []map[string]any `json:"rules"`
		}
		_ = json.Unmarshal(doc, &q)
		var out []string
		for _, qu := range q.Queues {
			out = append(out, fmt.Sprintf("queue %v bandwidth %v", qu["name"], qu["bandwidth"]))
		}
		for _, rl := range q.Rules {
			out = append(out, fmt.Sprintf("match %v on %v %v", rl["direction"], rl["interface"], rl["family"]))
		}
		writeJSON(w, 200, map[string]any{"rendered": out, "normalised": out})
	case parts[0] == "qos" && len(parts) == 2 && parts[1] == "drift":
		in := string(s.kernelQ) == string(s.qos)
		writeJSON(w, 200, map[string]any{"in_sync": in, "expected": []string{string(s.qos)}, "live": []string{string(s.kernelQ)}})
	case parts[0] == "changes" && len(parts) == 3 && r.Method == http.MethodPost:
		s.finish(w, actor, parts[1], parts[2])
	default:
		fail(w, 404, "not_found", "no route")
	}
}

func (s *Server) begin(w http.ResponseWriter, c *change) {
	s.seq++
	c.id = fmt.Sprintf("%016x", s.seq)
	s.pending = c
	writeJSON(w, 202, map[string]any{"id": c.id, "actor": c.actor, "kind": c.kind, "name": c.name, "op": c.op,
		"deadline": time.Now().Add(time.Minute), "etag": c.etag})
}

func (s *Server) anchor(w http.ResponseWriter, r *http.Request, actor, name string) {
	cur, exists := s.anchors[name]
	tag := ""
	if exists {
		tag = etag(cur)
	}
	switch r.Method {
	case http.MethodGet:
		if !exists {
			fail(w, 404, "not_found", "anchor")
			return
		}
		w.Header().Set("ETag", `"`+tag+`"`)
		writeJSON(w, 200, map[string]any{"anchor": map[string]any{"name": name, "rules": cur}, "etag": tag})
		return
	case http.MethodPut, http.MethodDelete:
	default:
		fail(w, 405, "invalid", "method")
		return
	}
	if s.pending != nil {
		s.conflict(w, "change "+s.pending.id+" is pending")
		return
	}
	switch {
	case r.Method == http.MethodPut && !exists && r.Header.Get("If-None-Match") != "*":
		fail(w, 412, "precondition", "creating needs If-None-Match: *")
		return
	case r.Method == http.MethodPut && exists && r.Header.Get("If-None-Match") == "*":
		fail(w, 412, "precondition", "object exists")
		return
	case exists && r.Header.Get("If-None-Match") != "*" && ifMatch(r) != tag:
		fail(w, 412, "precondition", "ETag mismatch")
		return
	case r.Method == http.MethodDelete && !exists:
		fail(w, 404, "not_found", "anchor")
		return
	}
	c := &change{actor: actor, kind: "anchor", name: name, op: "put", prevA: cur}
	if r.Method == http.MethodPut {
		var b struct {
			Rules json.RawMessage `json:"rules"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			fail(w, 400, "invalid", "bad body")
			return
		}
		if strings.Contains(string(b.Rules), RejectLabel) {
			fail(w, 422, "pf_rejected", "syntax error")
			return
		}
		// Store compact JSON, as pfapid's Go encoder would.
		var v any
		_ = json.Unmarshal(b.Rules, &v)
		c.nextA, _ = json.Marshal(v)
		c.etag = etag(c.nextA)
		s.kernelA[name] = c.nextA
	} else {
		c.op = "delete"
		delete(s.kernelA, name)
	}
	s.begin(w, c)
}

func (s *Server) table(w http.ResponseWriter, r *http.Request, actor, name string) {
	cur, ok := s.tables[name]
	if !ok {
		fail(w, 404, "not_found", "table is not managed")
		return
	}
	tag := etag(cur)
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("ETag", `"`+tag+`"`)
		writeJSON(w, 200, map[string]any{"table": map[string]any{"name": name, "entries": cur}, "etag": tag})
	case http.MethodPut:
		if s.pending != nil {
			s.conflict(w, "change pending")
			return
		}
		if ifMatch(r) != tag {
			fail(w, 412, "precondition", "ETag mismatch")
			return
		}
		var b struct {
			Entries []string `json:"entries"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			fail(w, 400, "invalid", "bad body")
			return
		}
		if b.Entries == nil {
			b.Entries = []string{}
		}
		s.kernelT[name] = b.Entries
		s.begin(w, &change{actor: actor, kind: "table", name: name, op: "put", prevT: cur, nextT: b.Entries, etag: etag(b.Entries)})
	default:
		fail(w, 405, "invalid", "method")
	}
}

// readQoS decodes a QoS body into compact canonical JSON. Rules must be
// match rules, like pfapid's QoS validation; RejectLabel gives a 422.
func (s *Server) readQoS(w http.ResponseWriter, r *http.Request) (json.RawMessage, bool) {
	var v map[string]any
	if json.NewDecoder(r.Body).Decode(&v) != nil {
		fail(w, 400, "invalid", "bad body")
		return nil, false
	}
	doc, _ := json.Marshal(v)
	if strings.Contains(string(doc), RejectLabel) {
		fail(w, 422, "pf_rejected", "syntax error")
		return nil, false
	}
	rules, _ := v["rules"].([]any)
	for _, rl := range rules {
		if m, _ := rl.(map[string]any); m["action"] != "match" {
			fail(w, 400, "invalid", "QoS rules classify only: action must be match")
			return nil, false
		}
	}
	return doc, true
}

func (s *Server) qosDoc(w http.ResponseWriter, r *http.Request, actor string) {
	tag := etag(s.qos)
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("ETag", `"`+tag+`"`)
		writeJSON(w, 200, map[string]any{"qos": s.qos, "etag": tag})
	case http.MethodPut:
		if s.pending != nil {
			s.conflict(w, "change pending")
			return
		}
		if ifMatch(r) != tag {
			fail(w, 412, "precondition", "ETag mismatch")
			return
		}
		doc, ok := s.readQoS(w, r)
		if !ok {
			return
		}
		s.kernelQ = doc
		s.begin(w, &change{actor: actor, kind: "qos", name: "qos", op: "put", prevQ: s.qos, nextQ: doc, etag: etag(doc)})
	default:
		fail(w, 405, "invalid", "method")
	}
}

// TamperQoS changes the "kernel" queues, to simulate drift.
func (s *Server) TamperQoS() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kernelQ = json.RawMessage(`{"tampered":true}`)
}

// QoS returns the committed QoS document.
func (s *Server) QoS() json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.qos
}

func (s *Server) finish(w http.ResponseWriter, actor, id, what string) {
	c := s.pending
	if c == nil || c.id != id {
		fail(w, 404, "not_found", "no pending change")
		return
	}
	if c.actor != actor {
		fail(w, 403, "forbidden", "not your change")
		return
	}
	switch what {
	case "confirm":
		if s.FailConfirm {
			fail(w, 500, "internal", "injected confirm failure")
			return
		}
		s.Confirms++
		switch c.kind {
		case "qos":
			s.qos = c.nextQ
		case "anchor":
			if c.op == "delete" {
				delete(s.anchors, c.name)
			} else {
				s.anchors[c.name] = c.nextA
			}
		default:
			s.tables[c.name] = c.nextT
		}
	case "rollback":
		s.Rollbacks++
		switch c.kind {
		case "qos":
			s.kernelQ = c.prevQ
		case "anchor":
			if c.prevA == nil {
				delete(s.kernelA, c.name)
			} else {
				s.kernelA[c.name] = c.prevA
			}
		default:
			s.kernelT[c.name] = c.prevT
		}
	default:
		fail(w, 404, "not_found", "no route")
		return
	}
	s.pending = nil
	w.WriteHeader(http.StatusNoContent)
}

// HoldPending makes another client's change pending for d, so changes
// from the tests get 409 until it clears.
// conflict answers 409 for a pending change (s.mu held).
func (s *Server) conflict(w http.ResponseWriter, msg string) {
	s.Conflicts++
	fail(w, 409, "conflict", msg)
	if s.releaseAfter > 0 {
		s.releaseAfter--
		if s.releaseAfter == 0 {
			s.pending = nil
		}
	}
}

// HoldPendingConflicts makes another client's change pending until it has
// been answered with n conflicts. Unlike HoldPending it does not depend on
// how fast the test's requests arrive.
func (s *Server) HoldPendingConflicts(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	s.pending = &change{id: fmt.Sprintf("%016x", s.seq), actor: "someone-else", kind: "anchor", name: "other", op: "put"}
	s.releaseAfter = n
}

func (s *Server) HoldPending(d time.Duration) {
	s.mu.Lock()
	s.seq++
	c := &change{id: fmt.Sprintf("%016x", s.seq), actor: "someone-else", kind: "anchor", name: "other", op: "put"}
	s.pending = c
	s.mu.Unlock()
	time.AfterFunc(d, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.pending == c {
			s.pending = nil
		}
	})
}
