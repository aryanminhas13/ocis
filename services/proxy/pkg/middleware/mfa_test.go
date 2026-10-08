package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	userpb "github.com/cs3org/go-cs3apis/cs3/identity/user/v1beta1"
	"github.com/owncloud/ocis/v2/ocis-pkg/log"
	"github.com/owncloud/ocis/v2/ocis-pkg/oidc"
	"github.com/owncloud/ocis/v2/services/proxy/pkg/config"
	revactx "github.com/owncloud/reva/v2/pkg/ctx"
	"github.com/stretchr/testify/assert"
	"go-micro.dev/v4/store"
)

var mfaTestUser = &userpb.User{Id: &userpb.UserId{OpaqueId: "user-1"}}

// mfaChain mirrors the proxy order: MultiFactor runs before the user is resolved,
// PersistMultiFactor after it.
func mfaChain(cfg config.MFAConfig, s store.Store, hasMFA *bool) http.Handler {
	resolveUser := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(revactx.ContextSetUser(r.Context(), mfaTestUser)))
		})
	}
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hasMFA = revactx.HasMFA(r.Context())
	})

	return MultiFactor(cfg, Logger(log.NopLogger()), MFAStore(s))(
		resolveUser(PersistMultiFactor(cfg, Logger(log.NopLogger()), MFAStore(s))(final)),
	)
}

func oidcRequest(acr string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/dav/spaces/vault", nil)
	return req.WithContext(oidc.NewContext(req.Context(), map[string]any{"acr": acr}))
}

// signedURLRequest has no OIDC claims, the SignedURLAuthenticator already added the user.
func signedURLRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/dav/spaces/vault?OC-Signature=abc", nil)
	return req.WithContext(revactx.ContextSetUser(req.Context(), mfaTestUser))
}

func TestMultiFactor_signedURLInheritsMFAFromOIDCRequest(t *testing.T) {
	cfg := config.MFAConfig{Enabled: true, AuthLevelNames: []string{"advanced"}, SessionDuration: 60}
	s := store.NewMemoryStore()
	var hasMFA bool

	mfaChain(cfg, s, &hasMFA).ServeHTTP(httptest.NewRecorder(), oidcRequest("advanced"))
	assert.True(t, hasMFA)

	records, err := s.Read(key(mfaTestUser.GetId().GetOpaqueId()))
	assert.NoError(t, err)
	assert.Len(t, records, 1)

	hasMFA = false
	mfaChain(cfg, s, &hasMFA).ServeHTTP(httptest.NewRecorder(), signedURLRequest())
	assert.True(t, hasMFA)
}

func TestMultiFactor_noMFAPersistedWithoutRequiredAcr(t *testing.T) {
	cfg := config.MFAConfig{Enabled: true, AuthLevelNames: []string{"advanced"}, SessionDuration: 60}
	s := store.NewMemoryStore()
	var hasMFA bool

	mfaChain(cfg, s, &hasMFA).ServeHTTP(httptest.NewRecorder(), oidcRequest("regular"))
	assert.False(t, hasMFA)

	_, err := s.Read(key(mfaTestUser.GetId().GetOpaqueId()))
	assert.ErrorIs(t, err, store.ErrNotFound)

	mfaChain(cfg, s, &hasMFA).ServeHTTP(httptest.NewRecorder(), signedURLRequest())
	assert.False(t, hasMFA)
}

func TestMultiFactor_signedURLWithoutPriorOIDCRequestHasNoMFA(t *testing.T) {
	cfg := config.MFAConfig{Enabled: true, AuthLevelNames: []string{"advanced"}, SessionDuration: 60}
	var hasMFA bool

	mfaChain(cfg, store.NewMemoryStore(), &hasMFA).ServeHTTP(httptest.NewRecorder(), signedURLRequest())
	assert.False(t, hasMFA)
}

func TestMultiFactor_expiredStoreEntryHasNoMFA(t *testing.T) {
	cfg := config.MFAConfig{Enabled: true, AuthLevelNames: []string{"advanced"}, SessionDuration: 60}
	s := store.NewMemoryStore()
	var hasMFA bool

	verifiedAt := time.Now().Add(-61 * time.Second).Unix()
	assert.NoError(t, s.Write(&store.Record{
		Key:   key(mfaTestUser.GetId().GetOpaqueId()),
		Value: []byte(strconv.FormatInt(verifiedAt, 10)),
	}))

	mfaChain(cfg, s, &hasMFA).ServeHTTP(httptest.NewRecorder(), signedURLRequest())
	assert.False(t, hasMFA)
}

func TestPersistMultiFactor_writesAtMostOncePerInterval(t *testing.T) {
	cfg := config.MFAConfig{Enabled: true, AuthLevelNames: []string{"advanced"}, SessionDuration: 60}
	s := store.NewMemoryStore()
	var hasMFA bool
	handler := mfaChain(cfg, s, &hasMFA)

	handler.ServeHTTP(httptest.NewRecorder(), oidcRequest("advanced"))
	assert.NoError(t, s.Delete(key(mfaTestUser.GetId().GetOpaqueId())))

	handler.ServeHTTP(httptest.NewRecorder(), oidcRequest("advanced"))
	_, err := s.Read(key(mfaTestUser.GetId().GetOpaqueId()))
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestPersistMultiFactor_disabled(t *testing.T) {
	cfg := config.MFAConfig{Enabled: false, AuthLevelNames: []string{"advanced"}}
	s := store.NewMemoryStore()
	var hasMFA bool

	mfaChain(cfg, s, &hasMFA).ServeHTTP(httptest.NewRecorder(), oidcRequest("advanced"))
	// MultiFactor always sets MFA when disabled, but nothing needs to be persisted
	assert.True(t, hasMFA)

	_, err := s.Read(key(mfaTestUser.GetId().GetOpaqueId()))
	assert.ErrorIs(t, err, store.ErrNotFound)
}
