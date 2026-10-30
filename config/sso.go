package config

import (
	"fmt"

	"gopkg.in/alecthomas/kingpin.v2"
)

const SSOProviderOIDC = "oidc"

var (
	ssoOIDCIssuerURL    = kingpin.Flag("sso-oidc-issuer-url", "OIDC issuer URL; enables SSO with OIDC").Envar("SSO_OIDC_ISSUER_URL").String()
	ssoOIDCClientID     = kingpin.Flag("sso-oidc-client-id", "OIDC client ID").Envar("SSO_OIDC_CLIENT_ID").String()
	ssoOIDCClientSecret = kingpin.Flag("sso-oidc-client-secret", "OIDC client secret").Envar("SSO_OIDC_CLIENT_SECRET").String()
	ssoDefaultRole      = kingpin.Flag("sso-default-role", "Role assigned to users created on their first SSO login (default Viewer)").Envar("SSO_DEFAULT_ROLE").String()
	ssoForce            = kingpin.Flag("sso-force", "Disable password login and only allow SSO").Envar("SSO_FORCE").Bool()
)

type SSO struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	Provider    string `yaml:"provider" json:"provider"`
	DefaultRole string `yaml:"defaultRole" json:"default_role"`
	ForceSSO    bool   `yaml:"forceSSO" json:"force_sso"`
	OIDC        *OIDC  `yaml:"oidc" json:"oidc,omitempty"`
}

type OIDC struct {
	IssuerURL    string `yaml:"issuerURL" json:"issuer_url"`
	ClientID     string `yaml:"clientID" json:"client_id"`
	ClientSecret string `yaml:"clientSecret" json:"client_secret"`
}

func (cfg *Config) applySSOFlags() {
	if *ssoOIDCIssuerURL == "" {
		return
	}
	cfg.SSO = &SSO{
		Enabled:     true,
		Provider:    SSOProviderOIDC,
		DefaultRole: *ssoDefaultRole,
		ForceSSO:    *ssoForce,
		OIDC: &OIDC{
			IssuerURL:    *ssoOIDCIssuerURL,
			ClientID:     *ssoOIDCClientID,
			ClientSecret: *ssoOIDCClientSecret,
		},
	}
}

func (s *SSO) Validate() error {
	if s == nil || !s.Enabled {
		return nil
	}
	if s.Provider != SSOProviderOIDC {
		return fmt.Errorf("unsupported provider %q: only oidc is implemented", s.Provider)
	}
	if s.OIDC == nil || s.OIDC.IssuerURL == "" || s.OIDC.ClientID == "" || s.OIDC.ClientSecret == "" {
		return fmt.Errorf("oidc requires issuerURL, clientID and clientSecret")
	}
	return nil
}
