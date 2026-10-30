package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coroot/coroot/config"
	"github.com/coroot/coroot/db"
	"github.com/coroot/coroot/rbac"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeIdP struct {
	*httptest.Server
	key      *rsa.PrivateKey
	clientID string
	secret   string
	email    string
	codes    map[string]url.Values
}

func newFakeIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	idp := &fakeIdP{key: key, clientID: "coroot", secret: "s3cret", email: "ana@example.com", codes: map[string]url.Values{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.URL,
			"authorization_endpoint":                idp.URL + "/authorize",
			"token_endpoint":                        idp.URL + "/token",
			"jwks_uri":                              idp.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "code-" + q.Get("state")
		idp.codes[code] = q
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, secret, _ := r.BasicAuth()
		if id == "" {
			id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		auth := idp.codes[r.Form.Get("code")]
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if id != idp.clientID || secret != idp.secret || auth == nil ||
			auth.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) ||
			auth.Get("redirect_uri") != r.Form.Get("redirect_uri") {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: idp.key}, (&jose.SignerOptions{}).WithHeader("kid", "k"))
		require.NoError(t, err)
		claims := map[string]any{
			"iss": idp.URL, "aud": idp.clientID, "sub": "ana", "nonce": auth.Get("nonce"),
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"email": idp.email, "given_name": "Ana", "family_name": "Lima",
		}
		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": token})
	})
	idp.Server = httptest.NewServer(mux)
	t.Cleanup(idp.Close)
	return idp
}

func newSSOTestApi(t *testing.T, idp *fakeIdP, force bool) (*Api, *httptest.Server) {
	database, err := db.NewSqlite(t.TempDir(), false)
	require.NoError(t, err)
	require.NoError(t, database.Migrate())
	cfg := config.NewConfig()
	require.NoError(t, cfg.Validate())
	cfg.SSO = &config.SSO{
		Enabled: true, Provider: config.SSOProviderOIDC, DefaultRole: "Editor", ForceSSO: force,
		OIDC: &config.OIDC{IssuerURL: idp.URL, ClientID: idp.clientID, ClientSecret: idp.secret},
	}
	a := NewApi(cfg, nil, database, nil, nil, nil, rbac.NewStaticRoleManager(), nil, nil, nil, "", "", nil)
	require.NoError(t, a.AuthInit("", "admin-password"))

	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", a.Login)
	mux.HandleFunc("/api/sso-status", a.SSOStatus)
	mux.HandleFunc("/api/sso-login", a.SSOLogin)
	mux.HandleFunc("/api/sso", a.Auth(a.SSO))
	mux.HandleFunc("/sso/oidc", a.SSOCallback)
	mux.HandleFunc("/api/whoami", a.Auth(func(w http.ResponseWriter, r *http.Request, u *db.User) {
		_, _ = w.Write([]byte(u.Email))
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return a, srv
}

func browser(t *testing.T) *http.Client {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &http.Client{Jar: jar}
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	resp, err := c.Get(u)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestSSOLogin(t *testing.T) {
	idp := newFakeIdP(t)
	a, srv := newSSOTestApi(t, idp, false)

	c := browser(t)
	resp, _ := get(t, c, srv.URL+"/api/sso-login?next="+url.QueryEscape("/p/abc/app?x=1"))
	assert.Equal(t, "/p/abc/app", resp.Request.URL.Path)
	assert.Equal(t, "x=1", resp.Request.URL.RawQuery)

	resp, body := get(t, c, srv.URL+"/api/whoami")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, idp.email, body)

	u, err := a.db.GetUserByEmail(idp.email)
	require.NoError(t, err)
	assert.Equal(t, "Ana Lima", u.Name)
	assert.Equal(t, []rbac.RoleName{"Editor"}, u.Roles)

	// The second login reuses the user.
	get(t, browser(t), srv.URL+"/api/sso-login")
	users, err := a.db.GetUsers()
	require.NoError(t, err)
	assert.Len(t, users, 2) // admin and ana

	// Password login still works when SSO is not forced; the admin sees the settings without the secret.
	admin := browser(t)
	resp, err = admin.Post(srv.URL+"/api/login", "application/json", strings.NewReader(`{"email":"admin","password":"admin-password"}`))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp, body = get(t, admin, srv.URL+"/api/sso")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, `"readonly":true`)
	assert.Contains(t, body, idp.clientID)
	assert.NotContains(t, body, idp.secret)
}

func TestSSOOpenRedirect(t *testing.T) {
	idp := newFakeIdP(t)
	_, srv := newSSOTestApi(t, idp, false)
	for _, next := range []string{"//evil.example/x", "https://evil.example/x", `/\evil.example`} {
		resp, _ := get(t, browser(t), srv.URL+"/api/sso-login?next="+url.QueryEscape(next))
		assert.Equal(t, strings.TrimPrefix(srv.URL, "http://"), resp.Request.URL.Host, next)
		assert.Equal(t, "/", resp.Request.URL.Path, next)
	}
}

func TestSSOStateMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	_, srv := newSSOTestApi(t, idp, false)
	c := browser(t)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	resp, _ := get(t, c, srv.URL+"/api/sso-login")
	require.Equal(t, http.StatusFound, resp.StatusCode)

	resp, _ = get(t, c, srv.URL+"/sso/oidc?code=forged&state=forged")
	assert.Equal(t, "/login?sso_error=1", resp.Header.Get("Location"))
	resp, _ = get(t, c, srv.URL+"/api/whoami")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Without the state cookie (e.g. login started in another browser).
	resp, _ = get(t, browser(t), srv.URL+"/sso/oidc?code=x&state=y")
	assert.Equal(t, "/login", resp.Request.URL.Path)
	assert.Equal(t, "sso_error=1", resp.Request.URL.RawQuery)
}

func TestSSOForce(t *testing.T) {
	idp := newFakeIdP(t)
	_, srv := newSSOTestApi(t, idp, true)

	resp, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(`{"email":"admin","password":"admin-password"}`))
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	_, body := get(t, browser(t), srv.URL+"/api/sso-status")
	assert.JSONEq(t, `{"enabled":true,"force_sso":true}`, body)

	c := browser(t)
	get(t, c, srv.URL+"/api/sso-login")
	resp, body = get(t, c, srv.URL+"/api/sso")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode) // Editor can't see SSO settings
	assert.NotContains(t, body, idp.secret)
}
