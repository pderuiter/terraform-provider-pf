package client_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pderuiter/terraform-provider-pf/internal/client"
	"github.com/pderuiter/terraform-provider-pf/internal/fakepfapid"
)

func newClient(t *testing.T, s *fakepfapid.Server) *client.Client {
	t.Helper()
	c, err := client.New(client.Config{Endpoint: s.URL, CACertPEM: s.CACertPEM, ClientCertPEM: s.ClientCertPEM, ClientKeyPEM: s.ClientKeyPEM})
	if err != nil {
		t.Fatal(err)
	}
	c.ConflictBackoff = 10 * time.Millisecond
	return c
}

var rules = []client.Rule{{Action: "pass", Direction: "in", Interface: "frontend", Family: "inet"}}

func TestConfigRefusesPlainHTTP(t *testing.T) {
	s := fakepfapid.New()
	defer s.Close()
	if _, err := client.New(client.Config{Endpoint: "http://fw:8443", CACertPEM: s.CACertPEM, ClientCertPEM: s.ClientCertPEM, ClientKeyPEM: s.ClientKeyPEM}); err == nil {
		t.Fatal("http endpoint accepted")
	}
}

func TestAnchorLifecycle(t *testing.T) {
	s := fakepfapid.New()
	defer s.Close()
	c := newClient(t, s)
	ctx := context.Background()

	who, err := c.Health(ctx)
	if err != nil || who != "tf-test" {
		t.Fatalf("health: %q %v", who, err)
	}
	if _, err := c.GetAnchor(ctx, "k8s"); !client.IsNotFound(err) {
		t.Fatalf("want not found, got %v", err)
	}
	ch, err := c.CreateAnchor(ctx, "k8s", rules)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.GetAnchor(ctx, "k8s")
	if err != nil || st.ETag != ch.ETag || len(st.Anchor.Rules) != 1 || s.Pending() {
		t.Fatalf("after create: %+v %v pending=%v", st, err, s.Pending())
	}
	if _, err := c.CreateAnchor(ctx, "k8s", rules); !client.IsPrecondition(err) {
		t.Fatalf("second create: %v", err)
	}
	if _, err := c.UpdateAnchor(ctx, "k8s", "stale", rules); !client.IsPrecondition(err) {
		t.Fatalf("stale update: %v", err)
	}
	if _, err := c.DeleteAnchor(ctx, "k8s", st.ETag); err != nil {
		t.Fatal(err)
	}
	if s.Anchor("k8s") != nil || s.Confirms != 2 {
		t.Fatalf("delete not committed (confirms=%d)", s.Confirms)
	}
}

func TestPfctlRejectionSurfaces(t *testing.T) {
	s := fakepfapid.New()
	defer s.Close()
	c := newClient(t, s)
	bad := []client.Rule{{Action: "pass", Interface: "frontend", Family: "inet", Label: fakepfapid.RejectLabel}}
	if _, err := c.ValidateAnchor(context.Background(), "k8s", bad); err == nil {
		t.Fatal("validate accepted a rejected rule")
	}
	if _, err := c.CreateAnchor(context.Background(), "k8s", bad); err == nil || s.Pending() {
		t.Fatalf("create: %v pending=%v", err, s.Pending())
	}
}

func TestConfirmFailureRollsBack(t *testing.T) {
	s := fakepfapid.New()
	defer s.Close()
	c := newClient(t, s)
	s.FailConfirm = true
	if _, err := c.CreateAnchor(context.Background(), "k8s", rules); err == nil {
		t.Fatal("unconfirmed change reported as success")
	}
	if s.Rollbacks != 1 || s.Pending() || s.Anchor("k8s") != nil {
		t.Fatalf("rollbacks=%d pending=%v", s.Rollbacks, s.Pending())
	}
}

// Parallel applies from one provider instance must queue, not collide.
func TestParallelChangesAreSerialised(t *testing.T) {
	s := fakepfapid.New("k8s_nodes")
	defer s.Close()
	c := newClient(t, s)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.CreateAnchor(ctx, n, rules)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if s.Conflicts != 0 || s.Confirms != 8 {
		t.Fatalf("conflicts=%d confirms=%d", s.Conflicts, s.Confirms)
	}
}

// Another client's pending change: retry until it clears, give up when
// the context ends.
func TestWaitsForForeignPendingChange(t *testing.T) {
	s := fakepfapid.New()
	defer s.Close()
	c := newClient(t, s)

	s.HoldPending(150 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.CreateAnchor(ctx, "y", rules); err != nil {
		t.Fatal(err)
	}
	if s.Conflicts == 0 {
		t.Fatal("expected at least one 409 while the foreign change was pending")
	}

	s.HoldPending(time.Hour)
	short, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	if _, err := c.CreateAnchor(short, "z", rules); !client.IsConflict(err) {
		t.Fatalf("want conflict after giving up, got %v", err)
	}
}

func TestTableReplace(t *testing.T) {
	s := fakepfapid.New("k8s_nodes")
	defer s.Close()
	c := newClient(t, s)
	ctx := context.Background()
	st, err := c.GetTable(ctx, "k8s_nodes")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReplaceTable(ctx, "k8s_nodes", st.ETag, []string{"10.0.0.1/32", "2001:db8::/64"}); err != nil {
		t.Fatal(err)
	}
	if got := s.Table("k8s_nodes"); len(got) != 2 {
		t.Fatalf("table: %v", got)
	}
	s.TamperTable("k8s_nodes", "192.0.2.1/32")
	d, err := c.DriftTable(ctx, "k8s_nodes")
	if err != nil || d.InSync {
		t.Fatalf("drift not detected: %+v %v", d, err)
	}
}
