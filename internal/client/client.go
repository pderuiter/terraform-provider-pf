// Package client talks to pfapid (api/openapi.yaml in wbyc/infra/pfapid)
// over mutual TLS and wraps its commit-confirm flow.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- wire types (mirror pfapid's JSON) -------------------------------------

type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to,omitempty"`
}

type Endpoint struct {
	Prefixes  []string    `json:"prefixes,omitempty"`
	Table     string      `json:"table,omitempty"`
	Interface string      `json:"interface,omitempty"`
	Ports     []PortRange `json:"ports,omitempty"`
}

type NAT struct {
	Kind      string     `json:"kind"`
	Address   string     `json:"address,omitempty"`
	Interface string     `json:"interface,omitempty"`
	Port      *PortRange `json:"port,omitempty"`
	ToFamily  string     `json:"to_family,omitempty"`
	AFFrom    string     `json:"af_from,omitempty"`
	AFTo      string     `json:"af_to,omitempty"`
}

type Prio struct {
	Normal uint8  `json:"normal"`
	Low    *uint8 `json:"low,omitempty"`
}

type Rule struct {
	Action      string   `json:"action"`
	Direction   string   `json:"direction,omitempty"`
	Quick       bool     `json:"quick,omitempty"`
	Log         bool     `json:"log,omitempty"`
	BlockReturn bool     `json:"block_return,omitempty"`
	Interface   string   `json:"interface"`
	Family      string   `json:"family"`
	Protocol    string   `json:"protocol,omitempty"`
	From        Endpoint `json:"from"`
	To          Endpoint `json:"to"`
	NAT         *NAT     `json:"nat,omitempty"`
	Prio        *Prio    `json:"prio,omitempty"`
	Label       string   `json:"label,omitempty"`
}

type Anchor struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

type AnchorState struct {
	Anchor        Anchor `json:"anchor"`
	ETag          string `json:"etag"`
	PendingChange string `json:"pending_change,omitempty"`
}

type Table struct {
	Name    string   `json:"name"`
	Entries []string `json:"entries"`
}

type TableState struct {
	Table         Table  `json:"table"`
	ETag          string `json:"etag"`
	PendingChange string `json:"pending_change,omitempty"`
}

type Change struct {
	ID       string    `json:"id"`
	Actor    string    `json:"actor"`
	Kind     string    `json:"kind"`
	Name     string    `json:"name"`
	Op       string    `json:"op"`
	Deadline time.Time `json:"deadline"`
	ETag     string    `json:"etag,omitempty"`
}

type Validation struct {
	Rendered   []string `json:"rendered"`
	Normalised []string `json:"normalised"`
}

type Drift struct {
	InSync   bool     `json:"in_sync"`
	Expected []string `json:"expected"`
	Live     []string `json:"live"`
}

// --- errors ---------------------------------------------------------------

// APIError is a non-2xx answer from pfapid.
type APIError struct {
	Status     int
	Code       string `json:"code"`
	Message    string `json:"message"`
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("pfapid: %d %s: %s", e.Status, e.Code, e.Message)
}

func IsNotFound(err error) bool     { return hasStatus(err, http.StatusNotFound) }
func IsPrecondition(err error) bool { return hasStatus(err, http.StatusPreconditionFailed) }
func IsConflict(err error) bool     { return hasStatus(err, http.StatusConflict) }

func hasStatus(err error, s int) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == s
}

// --- client ---------------------------------------------------------------

type Config struct {
	Endpoint      string // https://host:8443
	CACertPEM     []byte // CA that signed the pfapid server certificate
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	Timeout       time.Duration // per request
	UserAgent     string
}

type Client struct {
	base *url.URL
	http *http.Client
	ua   string

	// pfapid allows one pending change at a time; Terraform applies
	// resources in parallel. Changes from this provider instance queue here.
	changeMu sync.Mutex
	// Backoff while another client's change is pending (409).
	ConflictBackoff time.Duration
}

func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("endpoint %q must be an https URL", cfg.Endpoint)
	}
	cert, err := tls.X509KeyPair(cfg.ClientCertPEM, cfg.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.CACertPEM) {
		return nil, errors.New("ca_cert: no PEM certificates found")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
		},
		Proxy:               nil, // a firewall's management API is never reached through a proxy
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{
		base:            u,
		http:            &http.Client{Transport: tr, Timeout: cfg.Timeout},
		ua:              cfg.UserAgent,
		ConflictBackoff: 2 * time.Second,
	}, nil
}

func (c *Client) do(ctx context.Context, method, p string, hdr map[string]string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+p, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.ua != "" {
		req.Header.Set("User-Agent", c.ua)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		e := &APIError{Status: resp.StatusCode}
		var env struct {
			Error *APIError `json:"error"`
		}
		if json.Unmarshal(data, &env) == nil && env.Error != nil {
			e.Code, e.Message = env.Error.Code, env.Error.Message
		} else {
			e.Message = strings.TrimSpace(string(data))
		}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
			e.RetryAfter = time.Duration(s) * time.Second
		}
		return e
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decoding %s %s: %w", method, p, err)
		}
	}
	return nil
}

func quoted(etag string) string { return `"` + etag + `"` }

// --- reads ----------------------------------------------------------------

func (c *Client) Health(ctx context.Context) (string, error) {
	var v struct {
		Client string `json:"client"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/healthz", nil, nil, &v)
	return v.Client, err
}

func (c *Client) GetAnchor(ctx context.Context, name string) (*AnchorState, error) {
	var v AnchorState
	if err := c.do(ctx, http.MethodGet, "/v1/anchors/"+url.PathEscape(name), nil, nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *Client) ValidateAnchor(ctx context.Context, name string, rules []Rule) (*Validation, error) {
	var v Validation
	err := c.do(ctx, http.MethodPost, "/v1/anchors/"+url.PathEscape(name)+"/validate", nil, anchorBody(rules), &v)
	return &v, err
}

func (c *Client) DriftAnchor(ctx context.Context, name string) (*Drift, error) {
	var v Drift
	err := c.do(ctx, http.MethodGet, "/v1/anchors/"+url.PathEscape(name)+"/drift", nil, nil, &v)
	return &v, err
}

func (c *Client) GetTable(ctx context.Context, name string) (*TableState, error) {
	var v TableState
	if err := c.do(ctx, http.MethodGet, "/v1/tables/"+url.PathEscape(name), nil, nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *Client) DriftTable(ctx context.Context, name string) (*Drift, error) {
	var v Drift
	err := c.do(ctx, http.MethodGet, "/v1/tables/"+url.PathEscape(name)+"/drift", nil, nil, &v)
	return &v, err
}

func anchorBody(rules []Rule) any {
	if rules == nil {
		rules = []Rule{}
	}
	return map[string]any{"rules": rules}
}

// --- changes (commit-confirm) -----------------------------------------------

// commit runs one change: submit, then confirm. Submitting is retried while
// another change is pending (409) or the client is rate limited (429),
// until ctx ends. If the confirm fails the change is rolled back where
// possible; if pfapid cannot be reached at all, its deadline rolls it back.
func (c *Client) commit(ctx context.Context, submit func() (*Change, error)) (*Change, error) {
	c.changeMu.Lock()
	defer c.changeMu.Unlock()
	var ch *Change
	var last *APIError // the last 409/429, reported if we run out of time
	for {
		var err error
		ch, err = submit()
		if err == nil {
			break
		}
		var e *APIError
		if !errors.As(err, &e) {
			if last != nil && ctx.Err() != nil {
				return nil, fmt.Errorf("%w (gave up waiting: %w)", last, ctx.Err())
			}
			return nil, err
		}
		if e.Status != http.StatusConflict && e.Status != http.StatusTooManyRequests {
			return nil, err
		}
		last = e
		wait := c.ConflictBackoff
		if e.RetryAfter > 0 {
			wait = e.RetryAfter
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w (gave up waiting: %w)", err, ctx.Err())
		case <-time.After(wait):
		}
	}
	if err := c.Confirm(ctx, ch.ID); err != nil {
		// Best effort: undo now instead of waiting for the deadline. Use a
		// fresh context, ctx may be what failed.
		rctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if rerr := c.Rollback(rctx, ch.ID); rerr != nil {
			return nil, fmt.Errorf("change %s applied but not confirmed (%w); explicit rollback failed (%v), pfapid reverts it at %s",
				ch.ID, err, rerr, ch.Deadline.Format(time.RFC3339))
		}
		return nil, fmt.Errorf("change %s applied but not confirmed, rolled back: %w", ch.ID, err)
	}
	return ch, nil
}

func (c *Client) submit(ctx context.Context, method, p string, hdr map[string]string, body any) (*Change, error) {
	var ch Change
	if err := c.do(ctx, method, p, hdr, body, &ch); err != nil {
		return nil, err
	}
	if ch.ID == "" {
		return nil, fmt.Errorf("%s %s: no change id in response", method, p)
	}
	return &ch, nil
}

// CreateAnchor creates an anchor that must not exist yet.
func (c *Client) CreateAnchor(ctx context.Context, name string, rules []Rule) (*Change, error) {
	return c.commit(ctx, func() (*Change, error) {
		return c.submit(ctx, http.MethodPut, "/v1/anchors/"+url.PathEscape(name), map[string]string{"If-None-Match": "*"}, anchorBody(rules))
	})
}

// UpdateAnchor replaces the anchor's rules if its ETag is still etag.
func (c *Client) UpdateAnchor(ctx context.Context, name, etag string, rules []Rule) (*Change, error) {
	return c.commit(ctx, func() (*Change, error) {
		return c.submit(ctx, http.MethodPut, "/v1/anchors/"+url.PathEscape(name), map[string]string{"If-Match": quoted(etag)}, anchorBody(rules))
	})
}

func (c *Client) DeleteAnchor(ctx context.Context, name, etag string) (*Change, error) {
	return c.commit(ctx, func() (*Change, error) {
		return c.submit(ctx, http.MethodDelete, "/v1/anchors/"+url.PathEscape(name), map[string]string{"If-Match": quoted(etag)}, nil)
	})
}

// ReplaceTable sets the table's contents if its ETag is still etag.
func (c *Client) ReplaceTable(ctx context.Context, name, etag string, entries []string) (*Change, error) {
	if entries == nil {
		entries = []string{}
	}
	return c.commit(ctx, func() (*Change, error) {
		return c.submit(ctx, http.MethodPut, "/v1/tables/"+url.PathEscape(name), map[string]string{"If-Match": quoted(etag)}, map[string]any{"entries": entries})
	})
}

func (c *Client) Confirm(ctx context.Context, id string) error {
	err := c.do(ctx, http.MethodPost, "/v1/changes/"+url.PathEscape(id)+"/confirm", nil, nil, nil)
	return err
}

func (c *Client) Rollback(ctx context.Context, id string) error {
	err := c.do(ctx, http.MethodPost, "/v1/changes/"+url.PathEscape(id)+"/rollback", nil, nil, nil)
	return err
}
