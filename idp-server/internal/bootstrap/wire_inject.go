//go:build wireinject
// +build wireinject

package bootstrap

import (
	"context"

	"github.com/google/wire"
)

//go:generate wire
func initializeApp(ctx context.Context, cfg *config) (*App, error) {
	wire.Build(
		provideMySQLDatabases,
		provideRedis,
		provideKeySyncBroadcaster,
		provideKeyBuilder,
		provideSecretCodec,
		providePasswordVerifier,
		provideTOTPProvider,
		providePasskeyProvider,
		provideUserRepository,
		provideAuditStore,
		provideOperatorRoleRepository,
		provideSessionRepository,
		provideClientRepository,
		provideShortURLRepository,
		provideAuthorizationCodeRepository,
		provideConsentRepository,
		provideJWKRepository,
		provideTokenStore,
		provideTokenRepository,
		provideTOTPRepository,
		providePasskeyRepository,
		provideSessionCacheRepository,
		provideTokenCacheRepository,
		provideDeviceCodeRepository,
		provideMFARepository,
		provideReplayProtectionRepository,
		provideRateLimitRepository,
		provideAuditEventRepository,
		provideFederatedOIDCProvider,
		provideAuthnRegistry,
		provideAuthnService,
		provideAuthzService,
		provideConsentManager,
		provideRegisterService,
		provideRegistrar,
		providePasswordResetter,
		provideAccountUnlocker,
		provideClientService,
		provideClientCreator,
		provideClientRegistrar,
		provideClientPostLogoutRegistrar,
		provideLogoutRedirectValidator,
		provideSessionManager,
		provideRBACManager,
		provideShortURLManager,
		provideMFAService,
		providePasskeyService,
		provideRotationConfig,
		provideKeyManager,
		provideJWTService,
		provideTokenService,
		provideDeviceService,
		provideGrantRegistry,
		provideClientAuthRegistry,
		provideClientAuthenticator,
		provideOIDCService,
		provideAuthMiddleware,
		provideAdminMiddleware,
		provideKeysManager,
		provideRouter,
		provideApp,
	)
	return nil, nil
}
