package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gotify/server/v3/auth"
	"github.com/gotify/server/v3/decaymap"
	"github.com/gotify/server/v3/mode"
	"github.com/gotify/server/v3/model"
	"github.com/gotify/server/v3/test/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const testIssuer = "https://idp.example.com"

func TestOIDCSuite(t *testing.T) {
	suite.Run(t, new(OIDCSuite))
}

type OIDCSuite struct {
	suite.Suite
	db       *testdb.Database
	a        *OIDCAPI
	ctx      *gin.Context
	recorder *httptest.ResponseRecorder
	notified bool
}

func (s *OIDCSuite) BeforeTest(suiteName, testName string) {
	mode.Set(mode.TestDev)
	s.recorder = httptest.NewRecorder()
	s.ctx, _ = gin.CreateTestContext(s.recorder)
	s.db = testdb.NewDB(s.T())
	s.notified = false
	notifier := new(UserChangeNotifier)
	notifier.OnUserAdded(func(uint) error {
		s.notified = true
		return nil
	})
	s.a = &OIDCAPI{
		DB:                 s.db.GormDatabase,
		UserChangeNotifier: notifier,
		UsernameClaim:      "preferred_username",
		AutoRegister:       true,
		pendingSessions:    decaymap.NewDecayMap[string, *pendingOIDCSession](time.Now(), pendingSessionMaxAge),
	}
}

func (s *OIDCSuite) AfterTest(suiteName, testName string) {
	s.db.Close()
}

func (s *OIDCSuite) Test_GenerateState_Unique() {
	s1, _ := s.a.generateState()
	s2, _ := s.a.generateState()
	assert.NotEqual(s.T(), s1, s2)
}

// --- LoginHandler ---

func newDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"userinfo_endpoint":      server.URL + "/userinfo",
			"jwks_uri":               server.URL + "/keys",
		})
	})
	return server
}

func (s *OIDCSuite) Test_LoginHandler_AuthURL() {
	issuer := newDiscoveryServer(s.T())

	provider, err := rp.NewRelyingPartyOIDC(
		context.Background(), issuer.URL, "client", "secret", "https://gotify.example/callback", []string{"openid"},
	)
	assert.NoError(s.T(), err)
	s.a.Provider = provider

	tests := []struct {
		name       string
		prompt     []string
		wantPrompt string
	}{
		{name: "default prompt", prompt: []string{"login"}, wantPrompt: "login"},
		{name: "custom prompt", prompt: []string{"consent"}, wantPrompt: "consent"},
		{name: "empty prompt disables the parameter", prompt: []string{}, wantPrompt: ""},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			s.a.Prompt = tc.prompt
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest("GET", "/auth/oidc/login?name=testclient", nil)

			s.a.LoginHandler()(ctx)

			location, err := url.Parse(recorder.Header().Get("Location"))
			assert.NoError(s.T(), err)
			query := location.Query()
			assert.NotEmpty(s.T(), query.Get("state"))
			assert.Equal(s.T(), tc.wantPrompt, query.Get("prompt"))
			assert.Equal(s.T(), "client", query.Get("client_id"))
			assert.Equal(s.T(), "https://gotify.example/callback", query.Get("redirect_uri"))
			assert.Equal(s.T(), "openid", query.Get("scope"))
		})
	}
}

func (s *OIDCSuite) Test_ElevateHandler_AuthURL() {
	issuer := newDiscoveryServer(s.T())

	provider, err := rp.NewRelyingPartyOIDC(
		context.Background(), issuer.URL, "client", "secret", "https://gotify.example/callback", []string{"openid"},
	)
	assert.NoError(s.T(), err)
	s.a.Provider = provider
	s.a.Prompt = []string{"login"}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest("GET", "/auth/oidc/elevate?id=1&durationSeconds=60", nil)

	s.a.ElevateHandler(ctx)

	location, err := url.Parse(recorder.Header().Get("Location"))
	assert.NoError(s.T(), err)
	query := location.Query()
	assert.NotEmpty(s.T(), query.Get("state"))
	assert.Equal(s.T(), "login", query.Get("prompt"))
	assert.Equal(s.T(), "client", query.Get("client_id"))
	assert.Equal(s.T(), "https://gotify.example/callback", query.Get("redirect_uri"))
	assert.Equal(s.T(), "openid", query.Get("scope"))
}

func (s *OIDCSuite) Test_ResolveUser_ReturningUser_MatchedByOIDCID() {
	oidcID := testIssuer + "#sub-1"
	s.db.CreateUser(&model.User{ID: 1, Name: "alice", OIDCID: &oidcID})

	// The username claim differs from the stored name; the binding still matches.
	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{"preferred_username": "renamed"}}
	user, status, err := s.a.resolveUser(testIssuer, info)

	assert.NoError(s.T(), err)
	assert.Equal(s.T(), 0, status)
	assert.Equal(s.T(), uint(1), user.ID)
	assert.Equal(s.T(), "alice", user.Name)
	assert.False(s.T(), s.notified)
}

func (s *OIDCSuite) Test_ResolveUser_LinkByUsername_BindsExistingUser() {
	s.a.LinkByUsername = true
	s.db.NewUserWithName(1, "alice")

	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{"preferred_username": "alice"}}
	user, _, err := s.a.resolveUser(testIssuer, info)

	assert.NoError(s.T(), err)
	assert.Equal(s.T(), uint(1), user.ID)
	assert.NotNil(s.T(), user.OIDCID)
	assert.Equal(s.T(), testIssuer+"#sub-1", *user.OIDCID)
	// Binding an existing user is not a registration, so no notification.
	assert.False(s.T(), s.notified)

	bound, err := s.db.GetUserByOIDC(testIssuer + "#sub-1")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), bound)
	assert.Equal(s.T(), uint(1), bound.ID)
}

func (s *OIDCSuite) Test_ResolveUser_InvalidIssuer() {
	s.db.NewUserWithName(1, "alice")

	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{"preferred_username": "alice"}}
	_, status, err := s.a.resolveUser("://example.org", info)

	assert.EqualError(s.T(), err, `issuer url "://example.org" is not a valid url: parse "://example.org": missing protocol scheme`)
	assert.Equal(s.T(), 500, status)
}

func (s *OIDCSuite) Test_ResolveUser_InvalidIssuer_containsFragment() {
	s.db.NewUserWithName(1, "alice")

	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{"preferred_username": "alice"}}
	_, status, err := s.a.resolveUser(testIssuer+"#", info)

	assert.EqualError(s.T(), err, `issuer url "https://idp.example.com#" may not contain a fragment`)
	assert.Equal(s.T(), 500, status)
}

func (s *OIDCSuite) Test_ResolveUser_LinkDisabled_RejectsExistingUsername() {
	s.db.NewUserWithName(1, "alice")

	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{"preferred_username": "alice"}}
	_, status, err := s.a.resolveUser(testIssuer, info)

	assert.EqualError(s.T(), err, "a local user with the username alice already exists and linking by username is disabled")
	assert.Equal(s.T(), 403, status)

	// The existing user must not have been bound.
	user, _ := s.db.GetUserByName("alice")
	assert.Nil(s.T(), user.OIDCID)
}

func (s *OIDCSuite) Test_ResolveUser_LinkByUsername_RejectsDifferentIdentity() {
	s.a.LinkByUsername = true
	otherID := testIssuer + "#other-sub"
	s.db.CreateUser(&model.User{ID: 1, Name: "alice", OIDCID: &otherID})

	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{"preferred_username": "alice"}}
	_, status, err := s.a.resolveUser(testIssuer, info)

	assert.EqualError(s.T(), err, "the user alice is already bound to a different OIDC identity")
	assert.Equal(s.T(), 403, status)
}

func (s *OIDCSuite) Test_ResolveUser_AutoRegister() {
	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{"preferred_username": "newuser"}}
	user, status, err := s.a.resolveUser(testIssuer, info)

	assert.NoError(s.T(), err)
	assert.Equal(s.T(), 0, status)
	assert.Equal(s.T(), "newuser", user.Name)
	assert.False(s.T(), user.Admin)
	assert.NotNil(s.T(), user.OIDCID)
	assert.Equal(s.T(), testIssuer+"#sub-1", *user.OIDCID)
	assert.True(s.T(), s.notified)

	// Verify persisted and bound.
	dbUser, err := s.db.GetUserByOIDC(testIssuer + "#sub-1")
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), dbUser)
	assert.Equal(s.T(), "newuser", dbUser.Name)
}

func (s *OIDCSuite) Test_ResolveUser_AutoRegisterDisabled() {
	s.a.AutoRegister = false
	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{"preferred_username": "newuser"}}

	_, status, err := s.a.resolveUser(testIssuer, info)

	assert.EqualError(s.T(), err, "user does not exist and auto-registration is disabled")
	assert.Equal(s.T(), 403, status)
	s.db.AssertUsernameNotExist("newuser")
}

func (s *OIDCSuite) Test_ResolveUser_MissingIssuer() {
	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{"preferred_username": "newuser"}}

	_, status, err := s.a.resolveUser("", info)

	assert.EqualError(s.T(), err, "issuer claim was empty")
	assert.Equal(s.T(), 500, status)
}

func (s *OIDCSuite) Test_ResolveUser_MissingSubject() {
	info := &oidc.UserInfo{Claims: map[string]any{"preferred_username": "newuser"}}

	_, status, err := s.a.resolveUser(testIssuer, info)

	assert.EqualError(s.T(), err, "subject claim was empty")
	assert.Equal(s.T(), 500, status)
}

func (s *OIDCSuite) Test_ResolveUser_MissingClaim() {
	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{}}

	_, status, err := s.a.resolveUser(testIssuer, info)

	assert.EqualError(s.T(), err, `username claim "preferred_username" is missing`)
	assert.Equal(s.T(), 500, status)
}

func (s *OIDCSuite) Test_ResolveUser_EmptyClaim() {
	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{"preferred_username": ""}}

	_, status, err := s.a.resolveUser(testIssuer, info)

	assert.EqualError(s.T(), err, "username claim was empty")
	assert.Equal(s.T(), 500, status)
}

func (s *OIDCSuite) Test_ResolveUser_NilClaim() {
	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{"preferred_username": nil}}

	_, status, err := s.a.resolveUser(testIssuer, info)

	assert.EqualError(s.T(), err, "username claim was empty")
	assert.Equal(s.T(), 500, status)
}

func (s *OIDCSuite) Test_ResolveUser_CustomClaim() {
	s.a.UsernameClaim = "email"

	info := &oidc.UserInfo{Subject: "sub-1", Claims: map[string]any{"email": "new@example.com"}}
	user, status, err := s.a.resolveUser(testIssuer, info)

	assert.NoError(s.T(), err)
	assert.Equal(s.T(), 0, status)
	assert.Equal(s.T(), "new@example.com", user.Name)
	assert.NotNil(s.T(), user.OIDCID)
}

// --- createClient ---

func (s *OIDCSuite) Test_CreateClient() {
	s.db.NewUser(1)
	client, err := s.a.createClient("MyPhone", 1)

	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "MyPhone", client.Name)
	tokenParsed, err := auth.ParseEnhancedToken(client.Token)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), uint(1), client.UserID)
	assert.Equal(s.T(), uint(auth.CookieMaxAge), client.ExpiresAfterInactivitySeconds)

	dbClient, err := s.db.GetClientByToken(tokenParsed.PublicForm())
	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), dbClient)
}

// --- ExternalAuthorizeHandler ---

func (s *OIDCSuite) Test_ExternalAuthorizeHandler_AuthURL() {
	issuer := newDiscoveryServer(s.T())

	provider, err := rp.NewRelyingPartyOIDC(
		context.Background(), issuer.URL, "client", "secret", "https://gotify.example/callback", []string{"openid"},
	)
	assert.NoError(s.T(), err)
	s.a.Provider = provider
	s.a.Prompt = []string{"login"}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest("POST", "/auth/oidc/external/authorize", strings.NewReader(
		`{"code_challenge":"challenge","redirect_uri":"gotify://oidc/callback","name":"Android Phone"}`,
	))
	ctx.Request.Header.Set("Content-Type", "application/json")

	s.a.ExternalAuthorizeHandler(ctx)

	assert.Equal(s.T(), 200, recorder.Code)
	response := model.OIDCExternalAuthorizeResponse{}
	assert.NoError(s.T(), json.Unmarshal(recorder.Body.Bytes(), &response))
	authorizeURL, err := url.Parse(response.AuthorizeURL)
	assert.NoError(s.T(), err)
	query := authorizeURL.Query()
	assert.Equal(s.T(), response.State, query.Get("state"))
	assert.Equal(s.T(), "gotify://oidc/callback", query.Get("redirect_uri"))
	assert.Equal(s.T(), "challenge", query.Get("code_challenge"))
	assert.Equal(s.T(), "login", query.Get("prompt"))
	assert.Equal(s.T(), "client", query.Get("client_id"))
	assert.Equal(s.T(), "openid", query.Get("scope"))
}

func (s *OIDCSuite) Test_ExternalAuthorizeHandler_MissingFields() {
	s.ctx.Request = httptest.NewRequest("POST", "/auth/oidc/external/authorize", strings.NewReader(`{}`))
	s.ctx.Request.Header.Set("Content-Type", "application/json")

	s.a.ExternalAuthorizeHandler(s.ctx)

	assert.Equal(s.T(), 400, s.recorder.Code)
	assert.Contains(s.T(), s.ctx.Errors.Last().Error(), "'CodeChallenge' failed on the 'required' tag")
}

// --- ExternalTokenHandler ---

func (s *OIDCSuite) Test_ExternalTokenHandler_InvalidJSON() {
	s.ctx.Request = httptest.NewRequest("POST", "/auth/oidc/external/token", strings.NewReader(`{bad`))
	s.ctx.Request.Header.Set("Content-Type", "application/json")

	s.a.ExternalTokenHandler(s.ctx)

	assert.Equal(s.T(), 400, s.recorder.Code)
	assert.Contains(s.T(), s.ctx.Errors.Last().Error(), "invalid character")
}

func (s *OIDCSuite) Test_ExternalTokenHandler_UnknownState() {
	s.ctx.Request = httptest.NewRequest("POST", "/auth/oidc/external/token", strings.NewReader(
		`{"code":"abc","state":"bogus","code_verifier":"v"}`,
	))
	s.ctx.Request.Header.Set("Content-Type", "application/json")

	s.a.ExternalTokenHandler(s.ctx)

	assert.Equal(s.T(), 400, s.recorder.Code)
	assert.EqualError(s.T(), s.ctx.Errors.Last(), "unknown or expired state")
}
