package provider

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// Same rules as pfapid's model package.
var (
	nameRe  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}$`)
	labelRe = regexp.MustCompile(`^[A-Za-z0-9 _.:/-]{0,63}$`)
)

// cidrValidator requires canonical CIDR notation exactly as pfapid returns
// it (lower case, compressed IPv6, no host bits, explicit length), so what
// Terraform stores always equals what the API reads back.
type cidrValidator struct{}

func (cidrValidator) Description(context.Context) string {
	return "must be a canonical CIDR prefix such as 10.0.0.0/8, 192.0.2.10/32 or 2001:db8::/32"
}
func (v cidrValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v cidrValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if err := canonicalCIDR(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid prefix", err.Error())
	}
}

func canonicalCIDR(s string) error {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return fmt.Errorf("%q is not a CIDR prefix (write a single address as %s/32 or /128)", s, s)
	}
	if p.Addr().Zone() != "" || p.Addr().Is4In6() {
		return fmt.Errorf("%q: zoned and IPv4-mapped addresses are not supported", s)
	}
	if p.Masked() != p {
		return fmt.Errorf("%q has host bits set; did you mean %s?", s, p.Masked())
	}
	if p.String() != s {
		return fmt.Errorf("%q is not in canonical form; write %s", s, p)
	}
	return nil
}
