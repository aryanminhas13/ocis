package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/owncloud/reva/v2/pkg/autoprop"
	revactx "github.com/owncloud/reva/v2/pkg/ctx"
	microstore "go-micro.dev/v4/store"

	"github.com/owncloud/ocis/v2/ocis-pkg/log"
	"github.com/owncloud/ocis/v2/ocis-pkg/oidc"
	"github.com/owncloud/ocis/v2/services/proxy/pkg/config"
)

const defaultMFASessionDuration = 3600

// mfaStoreWriteInterval limits how often the MFA status of a user is written to the store.
const mfaStoreWriteInterval = time.Minute

// MultiFactor returns a middleware that checks requests for mfa
func MultiFactor(cfg config.MFAConfig, opts ...Option) func(next http.Handler) http.Handler {
	options := newOptions(opts...)
	logger := options.Logger

	sessionDuration := cfg.SessionDuration
	if sessionDuration <= 0 {
		sessionDuration = defaultMFASessionDuration
	}

	return func(next http.Handler) http.Handler {
		return &MultiFactorAuthentication{
			next:            next,
			logger:          logger,
			enabled:         cfg.Enabled,
			authLevelNames:  cfg.AuthLevelNames,
			store:           options.MFAStore,
			sessionDuration: time.Duration(sessionDuration) * time.Second,
		}
	}
}

// MultiFactorAuthentication is a authenticator that checks for mfa on specific paths
type MultiFactorAuthentication struct {
	next            http.Handler
	logger          log.Logger
	enabled         bool
	authLevelNames  []string
	sessionDuration time.Duration
	// store holds the MFA status persisted by PersistMultiFactor, so that non-OIDC
	// requests (e.g. signed-URL downloads) can inherit it from the user's most
	// recent OIDC session. Nil when no store is configured.
	store microstore.Store
}

// ServeHTTP adds the mfa header if the request contains a valid mfa token
func (m MultiFactorAuthentication) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Incoming requests must not have autopropagation headers
	for key, _ := range req.Header {
		if strings.HasPrefix(key, autoprop.HTTPAutoPropPrefix) || strings.HasPrefix(key, autoprop.MicroAutoPropPrefix) {
			req.Header.Del(key)
		}
	}

	if !m.enabled {
		// if mfa is disabled we always set the header to true.
		// this allows all other services to assume mfa is always active.
		// this should reduce code and configuration complexity in other services.
		req = req.WithContext(revactx.SetMFA(req.Context()))
		m.next.ServeHTTP(w, req)
		return
	}

	// overwrite the mfa header to avoid passing on wrong information
	ctx := revactx.RemoveMFA(req.Context())

	claims := oidc.FromContext(ctx)

	if claims == nil {
		// No OIDC claims — request was authenticated via a non-OIDC method
		// (e.g. signed URL, basic auth, app token). MFA cannot be determined
		// from claims directly.
		//
		// Fall back to the persisted MFA status from the user's most recent
		// OIDC-authenticated session. This allows, for example, a signed-URL
		// archiver download to succeed when the user has recently proven MFA
		// in their browser session.
		if m.store != nil {
			if u, ok := revactx.ContextGetUser(ctx); ok && u.GetId().GetOpaqueId() != "" {
				if m.readMFAFromStore(u.GetId().GetOpaqueId()) {
					ctx = revactx.SetMFA(ctx)
				}
			}
		}

		m.logger.Debug().Str("path", req.URL.Path).Bool("mfaStatus", revactx.HasMFA(ctx)).Msg("no OIDC claims in context")
		m.next.ServeHTTP(w, req.WithContext(ctx)) // ensure the request has the right context
		return
	}

	// acr is a standard OIDC claim.
	value, err := oidc.ReadStringClaim("acr", claims)
	if err != nil {
		m.logger.Debug().Str("path", req.URL.Path).Interface("required", m.authLevelNames).Err(err).Msg("acr claim not set in access token")
	} else if !m.containsMFA(value) {
		m.logger.Debug().Str("acr", value).Str("url", req.URL.Path).Msg("accessing path without mfa")
	} else {
		m.logger.Debug().Str("acr", value).Str("url", req.URL.Path).Msg("mfa authenticated")
		// The verified status is persisted by PersistMultiFactor, the user of an
		// OIDC request is only known after the AccountResolver ran.
		ctx = revactx.SetMFA(ctx)
	}

	// MFA status will only be true if the acr claim contains the proper value,
	// otherwise it wll be false (removed from the context early)
	m.next.ServeHTTP(w, req.WithContext(ctx))
}

// readMFAFromStore checks if the user had MFA in an OIDC request within the session duration.
// The age is checked here because stores like nats-js-kv don't support a per-record expiry.
func (m MultiFactorAuthentication) readMFAFromStore(userID string) bool {
	records, err := m.store.Read(key(userID))
	if err != nil || len(records) == 0 {
		return false
	}
	verifiedAt, err := strconv.ParseInt(string(records[0].Value), 10, 64)
	if err != nil {
		return false
	}
	return time.Since(time.Unix(verifiedAt, 0)) < m.sessionDuration
}

// PersistMultiFactor returns a middleware that stores when an OIDC request of a user last
// had MFA, so that non-OIDC requests (e.g. signed-URL downloads) can inherit it, see
// readMFAFromStore. The time is written at most once per mfaStoreWriteInterval and user.
//
// It must run after the AccountResolver, which adds the user of OIDC requests to the context.
func PersistMultiFactor(cfg config.MFAConfig, opts ...Option) func(next http.Handler) http.Handler {
	options := newOptions(opts...)

	lastWriteCache := ttlcache.New(
		ttlcache.WithTTL[string, struct{}](mfaStoreWriteInterval),
		ttlcache.WithDisableTouchOnHit[string, struct{}](),
	)
	go lastWriteCache.Start()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := req.Context()
			// claims are required, a signed-URL request must not extend its own MFA status
			if cfg.Enabled && options.MFAStore != nil && oidc.FromContext(ctx) != nil && revactx.HasMFA(ctx) {
				if u, ok := revactx.ContextGetUser(ctx); ok && u.GetId().GetOpaqueId() != "" {
					userID := u.GetId().GetOpaqueId()
					if !lastWriteCache.Has(userID) {
						if err := options.MFAStore.Write(&microstore.Record{
							Key:   key(userID),
							Value: []byte(strconv.FormatInt(time.Now().Unix(), 10)),
						}); err != nil {
							options.Logger.Error().Err(err).Str("userID", userID).Msg("failed to write MFA status to store")
						} else {
							lastWriteCache.Set(userID, struct{}{}, ttlcache.DefaultTTL)
						}
					}
				}
			}

			next.ServeHTTP(w, req)
		})
	}
}

// containsMFA checks if the given value is in the list of authentication level names
func (m MultiFactorAuthentication) containsMFA(value string) bool {
	for _, v := range m.authLevelNames {
		if v == value {
			return true
		}
	}
	return false
}

func key(userID string) string {
	return "mfa:" + userID
}
