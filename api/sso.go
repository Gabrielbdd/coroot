package api

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coroot/coroot/config"
	"github.com/coroot/coroot/db"
	"github.com/coroot/coroot/rbac"
	"github.com/coroot/coroot/utils"
	"golang.org/x/oauth2"
	"k8s.io/klog"
)

const (
	ssoSettingName     = "sso"
	ssoStateCookieName = "coroot_sso_state"
	ssoStateTTL        = 10 * time.Minute
	ssoCallbackPath    = "sso/oidc"
)

type ssoState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Next     string `json:"next"`
}

type ssoForm struct {
	Action      string        `json:"action"`
	Provider    string        `json:"provider"`
	DefaultRole rbac.RoleName `json:"default_role"`
	ForceSSO    bool          `json:"force_sso"`
	OIDC        *config.OIDC  `json:"oidc"`
}

var (
	oidcProviders     = map[string]*oidc.Provider{}
	oidcProvidersLock sync.Mutex
)

func oidcProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	oidcProvidersLock.Lock()
	defer oidcProvidersLock.Unlock()
	if p := oidcProviders[issuer]; p != nil {
		return p, nil
	}
	// The provider keeps using this context to refresh the signing keys.
	p, err := oidc.NewProvider(oidc.ClientContext(context.Background(), http.DefaultClient), issuer)
	if err != nil {
		return nil, err
	}
	oidcProviders[issuer] = p
	return p, nil
}

// ssoSettings returns the SSO settings and whether they come from the config (read-only in the UI).
func (api *Api) ssoSettings() (*config.SSO, bool, error) {
	if api.cfg.SSO != nil {
		return api.cfg.SSO, true, nil
	}
	var s config.SSO
	if err := api.db.GetSetting(ssoSettingName, &s); err != nil && !errors.Is(err, db.ErrNotFound) {
		return nil, false, err
	}
	return &s, false, nil
}

func (api *Api) ssoDefaultRole(s *config.SSO) (rbac.RoleName, error) {
	role := rbac.RoleName(s.DefaultRole)
	if role == "" {
		return rbac.RoleViewer, nil
	}
	roles, err := api.roles.GetRoles()
	if err != nil {
		return "", err
	}
	if !role.Valid(roles) {
		return "", fmt.Errorf("unknown role: %s", role)
	}
	return role, nil
}

func (api *Api) ssoForced() bool {
	s, _, err := api.ssoSettings()
	if err != nil {
		klog.Errorln(err)
		return false
	}
	return s.Enabled && s.ForceSSO
}

func (api *Api) SSO(w http.ResponseWriter, r *http.Request, u *db.User) {
	if !api.IsAllowed(u, rbac.Actions.Users().Edit()) {
		http.Error(w, "You are not allowed to configure SSO.", http.StatusForbidden)
		return
	}
	s, readonly, err := api.ssoSettings()
	if err != nil {
		klog.Errorln(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodPost {
		if readonly {
			http.Error(w, "Single Sign-On is configured through the config.", http.StatusForbidden)
			return
		}
		var form ssoForm
		if err = json.NewDecoder(r.Body).Decode(&form); err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		switch form.Action {
		case "disable":
			s.Enabled = false
		case "save":
			if form.Provider != config.SSOProviderOIDC || form.OIDC == nil {
				http.Error(w, "Only OIDC is supported.", http.StatusBadRequest)
				return
			}
			next := *s
			next.Provider = config.SSOProviderOIDC
			next.DefaultRole = string(form.DefaultRole)
			next.ForceSSO = form.ForceSSO
			oidcCfg := *form.OIDC
			if oidcCfg.ClientSecret == "" && s.OIDC != nil {
				oidcCfg.ClientSecret = s.OIDC.ClientSecret
			}
			next.OIDC = &oidcCfg
			next.Enabled = true
			if err = next.Validate(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if _, err = api.ssoDefaultRole(&next); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if _, err = oidcProvider(r.Context(), oidcCfg.IssuerURL); err != nil {
				http.Error(w, "OIDC discovery failed: "+err.Error(), http.StatusBadRequest)
				return
			}
			s = &next
		default:
			http.Error(w, "SAML is not supported.", http.StatusBadRequest)
			return
		}
		if err = api.db.SetSetting(ssoSettingName, s); err != nil {
			klog.Errorln(err)
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		return
	}

	roles, err := api.roles.GetRoles()
	if err != nil {
		klog.Errorln(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	defaultRole, err := api.ssoDefaultRole(s)
	if err != nil {
		defaultRole = rbac.RoleViewer
	}
	type oidcView struct {
		IssuerURL string `json:"issuer_url"`
		ClientID  string `json:"client_id"`
	}
	res := struct {
		Readonly    bool            `json:"readonly"`
		Enabled     bool            `json:"enabled"`
		ForceSSO    bool            `json:"force_sso"`
		Provider    string          `json:"sso_provider"`
		DefaultRole rbac.RoleName   `json:"default_role"`
		Roles       []rbac.RoleName `json:"roles"`
		OIDC        *oidcView       `json:"oidc,omitempty"`
	}{
		Readonly:    readonly,
		Enabled:     s.Enabled,
		ForceSSO:    s.ForceSSO,
		Provider:    config.SSOProviderOIDC,
		DefaultRole: defaultRole,
	}
	for _, role := range roles {
		res.Roles = append(res.Roles, role.Name)
	}
	if s.OIDC != nil {
		res.OIDC = &oidcView{IssuerURL: s.OIDC.IssuerURL, ClientID: s.OIDC.ClientID}
	}
	utils.WriteJson(w, res)
}

func (api *Api) SSOStatus(w http.ResponseWriter, r *http.Request) {
	s, _, err := api.ssoSettings()
	if err != nil {
		klog.Errorln(err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	utils.WriteJson(w, struct {
		Enabled  bool `json:"enabled"`
		ForceSSO bool `json:"force_sso"`
	}{Enabled: s.Enabled, ForceSSO: s.Enabled && s.ForceSSO})
}

func (api *Api) oauth2Config(r *http.Request, s *config.SSO, p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.OIDC.ClientID,
		ClientSecret: s.OIDC.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  api.GetAbsoluteUrl(r, api.cfg.UrlBasePath+ssoCallbackPath).String(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
}

func (api *Api) SSOLogin(w http.ResponseWriter, r *http.Request) {
	s, _, err := api.ssoSettings()
	if err != nil || !s.Enabled {
		api.ssoFail(w, r, err)
		return
	}
	p, err := oidcProvider(r.Context(), s.OIDC.IssuerURL)
	if err != nil {
		api.ssoFail(w, r, err)
		return
	}
	st := ssoState{
		State:    utils.RandomString(32),
		Nonce:    utils.RandomString(32),
		Verifier: oauth2.GenerateVerifier(),
		Next:     r.URL.Query().Get("next"),
	}
	if err = api.setSSOStateCookie(w, r, st); err != nil {
		api.ssoFail(w, r, err)
		return
	}
	authURL := api.oauth2Config(r, s, p).AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (api *Api) SSOCallback(w http.ResponseWriter, r *http.Request) {
	st, err := api.getSSOStateCookie(r)
	http.SetCookie(w, &http.Cookie{Name: ssoStateCookieName, Path: api.cfg.UrlBasePath, MaxAge: -1, HttpOnly: true})
	if err != nil {
		api.ssoFail(w, r, err)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		api.ssoFail(w, r, fmt.Errorf("identity provider: %s: %s", e, q.Get("error_description")))
		return
	}
	if q.Get("state") == "" || q.Get("state") != st.State {
		api.ssoFail(w, r, errors.New("state mismatch"))
		return
	}
	s, _, err := api.ssoSettings()
	if err != nil || !s.Enabled {
		api.ssoFail(w, r, err)
		return
	}
	p, err := oidcProvider(r.Context(), s.OIDC.IssuerURL)
	if err != nil {
		api.ssoFail(w, r, err)
		return
	}
	oc := api.oauth2Config(r, s, p)
	token, err := oc.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		api.ssoFail(w, r, err)
		return
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		api.ssoFail(w, r, errors.New("no id_token in the token response"))
		return
	}
	idToken, err := p.Verifier(&oidc.Config{ClientID: s.OIDC.ClientID}).Verify(r.Context(), rawIDToken)
	if err != nil {
		api.ssoFail(w, r, err)
		return
	}
	if idToken.Nonce != st.Nonce {
		api.ssoFail(w, r, errors.New("nonce mismatch"))
		return
	}
	var claims struct {
		Email      string `json:"email"`
		Name       string `json:"name"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
	}
	if err = idToken.Claims(&claims); err != nil {
		api.ssoFail(w, r, err)
		return
	}
	if claims.Email == "" {
		ui, err := p.UserInfo(r.Context(), oauth2.StaticTokenSource(token))
		if err != nil {
			api.ssoFail(w, r, err)
			return
		}
		if err = ui.Claims(&claims); err != nil {
			api.ssoFail(w, r, err)
			return
		}
	}
	if claims.Email == "" {
		api.ssoFail(w, r, errors.New("the identity provider returned no email"))
		return
	}
	name := strings.TrimSpace(claims.GivenName + " " + claims.FamilyName)
	if name == "" {
		name = claims.Name
	}
	if name == "" {
		name = claims.Email
	}

	userId, err := api.ssoUser(s, claims.Email, name)
	if err != nil {
		api.ssoFail(w, r, err)
		return
	}
	if err = api.SetSessionCookie(w, userId, SessionCookieTTL); err != nil {
		api.ssoFail(w, r, err)
		return
	}
	http.Redirect(w, r, api.ssoRedirectPath(st.Next), http.StatusFound)
}

// ssoUser finds the user by email or creates it with the default role.
// SSO users get a random password, so they can't log in with a password unless an admin sets one.
func (api *Api) ssoUser(s *config.SSO, email, name string) (int, error) {
	u, err := api.db.GetUserByEmail(email)
	if err == nil {
		if u.IsServiceAccount() {
			return 0, fmt.Errorf("%s is a service account", email)
		}
		return u.Id, nil
	}
	if !errors.Is(err, db.ErrNotFound) {
		return 0, err
	}
	role, err := api.ssoDefaultRole(s)
	if err != nil {
		return 0, err
	}
	if err = api.db.AddUser(email, utils.RandomString(32), name, role); err != nil && !errors.Is(err, db.ErrConflict) {
		return 0, err
	}
	klog.Infof("SSO: created user %s with role %s", email, role)
	if u, err = api.db.GetUserByEmail(email); err != nil {
		return 0, err
	}
	return u.Id, nil
}

// ssoRedirectPath accepts only a local path, as set by the UI, to avoid an open redirect.
func (api *Api) ssoRedirectPath(next string) string {
	base := api.cfg.UrlBasePath
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, "\\") {
		return base
	}
	if strings.HasPrefix(next, base) {
		return next
	}
	return base + strings.TrimPrefix(next, "/")
}

func (api *Api) ssoFail(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		klog.Errorln("SSO:", err)
	}
	http.Redirect(w, r, api.cfg.UrlBasePath+"login?sso_error=1", http.StatusFound)
}

func (api *Api) setSSOStateCookie(w http.ResponseWriter, r *http.Request, st ssoState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	h := hmac.New(HashFunc.New, []byte(api.authSecret))
	h.Write(data)
	http.SetCookie(w, &http.Cookie{
		Name:     ssoStateCookieName,
		Value:    base64.URLEncoding.EncodeToString(data) + "." + base64.URLEncoding.EncodeToString(h.Sum(nil)),
		Path:     api.cfg.UrlBasePath,
		MaxAge:   int(ssoStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   fullURL(r).Scheme == "https",
		// Lax: the cookie must come back on the top-level redirect from the identity provider.
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (api *Api) getSSOStateCookie(r *http.Request) (*ssoState, error) {
	c, err := r.Cookie(ssoStateCookieName)
	if err != nil {
		return nil, errors.New("no SSO state cookie")
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid SSO state")
	}
	data, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	sig, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	h := hmac.New(HashFunc.New, []byte(api.authSecret))
	h.Write(data)
	if !hmac.Equal(sig, h.Sum(nil)) {
		return nil, errors.New("invalid SSO state signature")
	}
	var st ssoState
	if err = json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}
