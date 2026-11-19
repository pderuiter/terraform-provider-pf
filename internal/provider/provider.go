// Package provider implements the pf Terraform provider for pfapid.
package provider

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pderuiter/terraform-provider-pf/internal/client"
)

// Environment variables read when the matching provider argument is unset.
// The PEM arguments take the PEM text or a path to a PEM file.
const (
	envEndpoint   = "PFAPID_ENDPOINT"
	envCACert     = "PFAPID_CA_CERT"
	envClientCert = "PFAPID_CLIENT_CERT"
	envClientKey  = "PFAPID_CLIENT_KEY" // #nosec G101 -- variable name, not a credential
	envTimeout    = "PFAPID_TIMEOUT"
	envChangeWait = "PFAPID_CHANGE_WAIT"
)

var _ provider.Provider = &pfProvider{}

type pfProvider struct {
	version string
}

type providerModel struct {
	Endpoint   types.String `tfsdk:"endpoint"`
	CACert     types.String `tfsdk:"ca_cert"`
	ClientCert types.String `tfsdk:"client_cert"`
	ClientKey  types.String `tfsdk:"client_key"`
	Timeout    types.Int64  `tfsdk:"timeout"`
	ChangeWait types.Int64  `tfsdk:"change_wait"`
}

// providerData is what resources receive from Configure.
type providerData struct {
	client     *client.Client
	changeWait time.Duration
}

// New returns a provider factory for the given version.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &pfProvider{version: version} }
}

func (p *pfProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pf"
	resp.Version = p.version
}

func pemDesc(what, env string) string {
	return what + " in PEM form, or the path of a PEM file. Can also be set with the `" + env + "` environment variable."
}

func (p *pfProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages OpenBSD pf anchors and tables through [pfapid](https://gitlab.bsdserver.nl/wbyc/infra/pfapid), " +
			"authenticating with a client certificate (mutual TLS 1.3).",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "pfapid URL, e.g. `https://192.0.2.1:8443` (the firewall's management address). " +
					"Can also be set with the `" + envEndpoint + "` environment variable.",
				Optional: true,
			},
			"ca_cert": schema.StringAttribute{
				MarkdownDescription: pemDesc("CA certificate that signed the pfapid server certificate,", envCACert),
				Optional:            true,
			},
			"client_cert": schema.StringAttribute{
				MarkdownDescription: pemDesc("Client certificate, identified by its CN or SPIFFE ID; may include intermediates after the leaf,", envClientCert),
				Optional:            true,
			},
			"client_key": schema.StringAttribute{
				MarkdownDescription: pemDesc("Private key of the client certificate,", envClientKey),
				Optional:            true,
				Sensitive:           true,
			},
			"timeout": schema.Int64Attribute{
				MarkdownDescription: "Timeout in seconds for each API request. Defaults to `30`. " +
					"Can also be set with the `" + envTimeout + "` environment variable.",
				Optional: true,
			},
			"change_wait": schema.Int64Attribute{
				MarkdownDescription: "Seconds a change waits while another client's change is pending on the firewall " +
					"(pfapid allows one at a time). Defaults to `300`. Can also be set with the `" + envChangeWait + "` environment variable.",
				Optional: true,
			},
		},
	}
}

func stringOrEnv(v types.String, env string) string {
	if !v.IsNull() && !v.IsUnknown() {
		return v.ValueString()
	}
	return os.Getenv(env)
}

func intOrEnv(v types.Int64, env string, def int64) (int64, error) {
	if !v.IsNull() && !v.IsUnknown() {
		return v.ValueInt64(), nil
	}
	if s := os.Getenv(env); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", env, err)
		}
		return n, nil
	}
	return def, nil
}

// loadPEM accepts PEM text or a file path.
func loadPEM(v string) ([]byte, error) {
	if strings.Contains(v, "-----BEGIN ") {
		return []byte(v), nil
	}
	b, err := os.ReadFile(v) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (p *pfProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for attr, v := range map[string]types.String{"endpoint": cfg.Endpoint, "ca_cert": cfg.CACert, "client_cert": cfg.ClientCert, "client_key": cfg.ClientKey} {
		if v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(attr), "Unknown pf provider value",
				"The provider cannot be configured with a value that is only known after apply.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := stringOrEnv(cfg.Endpoint, envEndpoint)
	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Missing pfapid endpoint",
			"Set the endpoint provider argument or the "+envEndpoint+" environment variable.")
	}
	pems := map[string][]byte{}
	for _, a := range []struct {
		attr, env string
		v         types.String
	}{{"ca_cert", envCACert, cfg.CACert}, {"client_cert", envClientCert, cfg.ClientCert}, {"client_key", envClientKey, cfg.ClientKey}} {
		s := stringOrEnv(a.v, a.env)
		if s == "" {
			resp.Diagnostics.AddAttributeError(path.Root(a.attr), "Missing "+a.attr,
				"Set the "+a.attr+" provider argument or the "+a.env+" environment variable.")
			continue
		}
		b, err := loadPEM(s)
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root(a.attr), "Unreadable "+a.attr, err.Error())
			continue
		}
		pems[a.attr] = b
	}
	timeout, err := intOrEnv(cfg.Timeout, envTimeout, 30)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("timeout"), "Invalid timeout", err.Error())
	}
	wait, err := intOrEnv(cfg.ChangeWait, envChangeWait, 300)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("change_wait"), "Invalid change_wait", err.Error())
	}
	if resp.Diagnostics.HasError() {
		return
	}

	c, err := client.New(client.Config{
		Endpoint:      endpoint,
		CACertPEM:     pems["ca_cert"],
		ClientCertPEM: pems["client_cert"],
		ClientKeyPEM:  pems["client_key"],
		Timeout:       time.Duration(timeout) * time.Second,
		UserAgent:     "terraform-provider-pf/" + p.version,
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create pfapid client", err.Error())
		return
	}
	d := &providerData{client: c, changeWait: time.Duration(wait) * time.Second}
	resp.ResourceData = d
	resp.DataSourceData = d
}

func (p *pfProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewAnchorResource, NewTableResource, NewQoSResource}
}

func (p *pfProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}
