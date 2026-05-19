package bootstrap

import (
	"errors"
	"fmt"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	cacheRedis "idp-server/internal/infrastructure/cache/redis"

	"github.com/spf13/viper"
)

const (
	defaultConfigName = "idp"
)

type config struct {
	MySQLDSN                      string
	MySQLReadDSN                  string
	MySQLStrongReadSessionByID    bool
	MySQLStrongReadTokenBySHA256  bool
	RedisAddr                     string
	RedisPassword                 string
	RedisDB                       int
	RedisKeyPrefix                string
	RedisSentinelAddrs            string
	RedisMasterName               string
	AppEnv                        string
	AuditAsyncEnabled             bool
	AuditStream                   string
	AuditDLQStream                string
	AuditConsumerGroup            string
	AuditConsumerName             string
	AuditBatchSize                int
	AuditDedupTTL                 time.Duration
	AuditRetryTTL                 time.Duration
	AuditBlockTimeout             time.Duration
	AuditReclaimIdle              time.Duration
	AuditReclaimInterval          time.Duration
	AuditMaxRetryCount            int
	SessionTTL                    time.Duration
	Issuer                        string
	TOTPIssuer                    string
	JWTKeyID                      string
	WorkDir                       string
	SigningKeyDir                 string
	SigningKeyBits                int
	SigningKeyCheckInterval       time.Duration
	SigningKeyRotateBefore        time.Duration
	SigningKeyRetireAfter         time.Duration
	FederatedOIDCIssuer           string
	FederatedOIDCClientID         string
	FederatedOIDCClientSecret     string
	FederatedOIDCRedirectURI      string
	FederatedOIDCProviderName     string
	FederatedOIDCClientAuthMethod string
	FederatedOIDCUsernameClaim    string
	FederatedOIDCDisplayNameClaim string
	FederatedOIDCEmailClaim       string
	FederatedOIDCScopes           []string
	FederatedOIDCStateTTL         time.Duration
	LoginFailureWindow            time.Duration
	LoginMaxFailuresPerIP         int
	LoginMaxFailuresPerUser       int
	LoginUserLockThreshold        int
	LoginUserLockTTL              time.Duration
	ForceMFAEnrollment            bool
	PasskeyEnabled                bool
	PasskeyRPID                   string
	PasskeyRPDisplayName          string
	PasskeyRPOrigins              []string
	TOTPSecretEncryptionKey       string
}

type envBinding struct {
	key  string
	envs []string
}

var configEnvBindings = []envBinding{
	{key: "mysql.dsn", envs: []string{"MYSQL_DSN", "IDP_MYSQL_DSN"}},
	{key: "mysql.read_dsn", envs: []string{"MYSQL_READ_DSN", "IDP_MYSQL_READ_DSN"}},
	{key: "mysql.strong_read.session_by_id", envs: []string{"MYSQL_STRONG_READ_SESSION_BY_ID", "IDP_MYSQL_STRONG_READ_SESSION_BY_ID"}},
	{key: "mysql.strong_read.token_by_sha256", envs: []string{"MYSQL_STRONG_READ_TOKEN_BY_SHA256", "IDP_MYSQL_STRONG_READ_TOKEN_BY_SHA256"}},
	{key: "mysql.host", envs: []string{"MYSQL_HOST", "IDP_MYSQL_HOST"}},
	{key: "mysql.port", envs: []string{"MYSQL_PORT", "IDP_MYSQL_PORT"}},
	{key: "mysql.database", envs: []string{"MYSQL_DATABASE", "IDP_MYSQL_DATABASE"}},
	{key: "mysql.user", envs: []string{"MYSQL_USER", "IDP_MYSQL_USER"}},
	{key: "mysql.password", envs: []string{"MYSQL_PASSWORD", "IDP_MYSQL_PASSWORD"}},
	{key: "redis.addr", envs: []string{"REDIS_ADDR", "IDP_REDIS_ADDR"}},
	{key: "redis.host", envs: []string{"REDIS_HOST", "IDP_REDIS_HOST"}},
	{key: "redis.port", envs: []string{"REDIS_PORT", "IDP_REDIS_PORT"}},
	{key: "redis.password", envs: []string{"REDIS_PASSWORD", "IDP_REDIS_PASSWORD"}},
	{key: "redis.db", envs: []string{"REDIS_DB", "IDP_REDIS_DB"}},
	{key: "redis.key_prefix", envs: []string{"REDIS_KEY_PREFIX", "IDP_REDIS_KEY_PREFIX"}},
	{key: "redis.sentinel_addrs", envs: []string{"REDIS_SENTINEL_ADDRS", "IDP_REDIS_SENTINEL_ADDRS"}},
	{key: "redis.master_name", envs: []string{"REDIS_MASTER_NAME", "IDP_REDIS_MASTER_NAME"}},
	{key: "app.env", envs: []string{"APP_ENV", "IDP_APP_ENV"}},
	{key: "audit.async_enabled", envs: []string{"AUDIT_ASYNC_ENABLED", "IDP_AUDIT_ASYNC_ENABLED"}},
	{key: "audit.stream", envs: []string{"AUDIT_STREAM", "IDP_AUDIT_STREAM"}},
	{key: "audit.dlq_stream", envs: []string{"AUDIT_DLQ_STREAM", "IDP_AUDIT_DLQ_STREAM"}},
	{key: "audit.consumer_group", envs: []string{"AUDIT_CONSUMER_GROUP", "IDP_AUDIT_CONSUMER_GROUP"}},
	{key: "audit.consumer_name", envs: []string{"AUDIT_CONSUMER_NAME", "IDP_AUDIT_CONSUMER_NAME"}},
	{key: "audit.batch_size", envs: []string{"AUDIT_BATCH_SIZE", "IDP_AUDIT_BATCH_SIZE"}},
	{key: "audit.dedup_ttl", envs: []string{"AUDIT_DEDUP_TTL", "IDP_AUDIT_DEDUP_TTL"}},
	{key: "audit.retry_ttl", envs: []string{"AUDIT_RETRY_TTL", "IDP_AUDIT_RETRY_TTL"}},
	{key: "audit.block_timeout", envs: []string{"AUDIT_BLOCK_TIMEOUT", "IDP_AUDIT_BLOCK_TIMEOUT"}},
	{key: "audit.reclaim_idle", envs: []string{"AUDIT_RECLAIM_IDLE", "IDP_AUDIT_RECLAIM_IDLE"}},
	{key: "audit.reclaim_interval", envs: []string{"AUDIT_RECLAIM_INTERVAL", "IDP_AUDIT_RECLAIM_INTERVAL"}},
	{key: "audit.max_retry_count", envs: []string{"AUDIT_MAX_RETRY_COUNT", "IDP_AUDIT_MAX_RETRY_COUNT"}},
	{key: "session.ttl", envs: []string{"SESSION_TTL", "IDP_SESSION_TTL"}},
	{key: "issuer", envs: []string{"ISSUER", "IDP_ISSUER"}},
	{key: "totp.issuer", envs: []string{"TOTP_ISSUER", "IDP_TOTP_ISSUER"}},
	{key: "totp.secret_encryption_key", envs: []string{"TOTP_SECRET_ENCRYPTION_KEY", "IDP_TOTP_SECRET_ENCRYPTION_KEY"}},
	{key: "jwt.key_id", envs: []string{"JWT_KEY_ID", "IDP_JWT_KEY_ID"}},
	{key: "signing_key.dir", envs: []string{"SIGNING_KEY_DIR", "IDP_SIGNING_KEY_DIR"}},
	{key: "signing_key.bits", envs: []string{"SIGNING_KEY_BITS", "IDP_SIGNING_KEY_BITS"}},
	{key: "signing_key.check_interval", envs: []string{"SIGNING_KEY_CHECK_INTERVAL", "IDP_SIGNING_KEY_CHECK_INTERVAL"}},
	{key: "signing_key.rotate_before", envs: []string{"SIGNING_KEY_ROTATE_BEFORE", "IDP_SIGNING_KEY_ROTATE_BEFORE"}},
	{key: "signing_key.retire_after", envs: []string{"SIGNING_KEY_RETIRE_AFTER", "IDP_SIGNING_KEY_RETIRE_AFTER"}},
	{key: "federated_oidc.issuer", envs: []string{"FEDERATED_OIDC_ISSUER", "IDP_FEDERATED_OIDC_ISSUER"}},
	{key: "federated_oidc.client_id", envs: []string{"FEDERATED_OIDC_CLIENT_ID", "IDP_FEDERATED_OIDC_CLIENT_ID"}},
	{key: "federated_oidc.client_secret", envs: []string{"FEDERATED_OIDC_CLIENT_SECRET", "IDP_FEDERATED_OIDC_CLIENT_SECRET"}},
	{key: "federated_oidc.redirect_uri", envs: []string{"FEDERATED_OIDC_REDIRECT_URI", "IDP_FEDERATED_OIDC_REDIRECT_URI"}},
	{key: "federated_oidc.provider_name", envs: []string{"FEDERATED_OIDC_PROVIDER_NAME", "IDP_FEDERATED_OIDC_PROVIDER_NAME"}},
	{key: "federated_oidc.client_auth_method", envs: []string{"FEDERATED_OIDC_CLIENT_AUTH_METHOD", "IDP_FEDERATED_OIDC_CLIENT_AUTH_METHOD"}},
	{key: "federated_oidc.username_claim", envs: []string{"FEDERATED_OIDC_USERNAME_CLAIM", "IDP_FEDERATED_OIDC_USERNAME_CLAIM"}},
	{key: "federated_oidc.display_name_claim", envs: []string{"FEDERATED_OIDC_DISPLAY_NAME_CLAIM", "IDP_FEDERATED_OIDC_DISPLAY_NAME_CLAIM"}},
	{key: "federated_oidc.email_claim", envs: []string{"FEDERATED_OIDC_EMAIL_CLAIM", "IDP_FEDERATED_OIDC_EMAIL_CLAIM"}},
	{key: "federated_oidc.scopes", envs: []string{"FEDERATED_OIDC_SCOPES", "IDP_FEDERATED_OIDC_SCOPES"}},
	{key: "federated_oidc.state_ttl", envs: []string{"FEDERATED_OIDC_STATE_TTL", "IDP_FEDERATED_OIDC_STATE_TTL"}},
	{key: "login.failure_window", envs: []string{"LOGIN_FAILURE_WINDOW", "IDP_LOGIN_FAILURE_WINDOW"}},
	{key: "login.max_failures_per_ip", envs: []string{"LOGIN_MAX_FAILURES_PER_IP", "IDP_LOGIN_MAX_FAILURES_PER_IP"}},
	{key: "login.max_failures_per_user", envs: []string{"LOGIN_MAX_FAILURES_PER_USER", "IDP_LOGIN_MAX_FAILURES_PER_USER"}},
	{key: "login.user_lock_threshold", envs: []string{"LOGIN_USER_LOCK_THRESHOLD", "IDP_LOGIN_USER_LOCK_THRESHOLD"}},
	{key: "login.user_lock_ttl", envs: []string{"LOGIN_USER_LOCK_TTL", "IDP_LOGIN_USER_LOCK_TTL"}},
	{key: "mfa.force_enrollment", envs: []string{"FORCE_MFA_ENROLLMENT", "IDP_FORCE_MFA_ENROLLMENT"}},
	{key: "passkey.enabled", envs: []string{"PASSKEY_ENABLED", "IDP_PASSKEY_ENABLED"}},
	{key: "passkey.rp_id", envs: []string{"PASSKEY_RP_ID", "IDP_PASSKEY_RP_ID"}},
	{key: "passkey.rp_display_name", envs: []string{"PASSKEY_RP_DISPLAY_NAME", "IDP_PASSKEY_RP_DISPLAY_NAME"}},
	{key: "passkey.rp_origins", envs: []string{"PASSKEY_RP_ORIGINS", "IDP_PASSKEY_RP_ORIGINS"}},
	{key: "config.file", envs: []string{"IDP_CONFIG_FILE"}},
	{key: "config.name", envs: []string{"IDP_CONFIG_NAME"}},
	{key: "config.type", envs: []string{"IDP_CONFIG_TYPE"}},
	{key: "config.paths", envs: []string{"IDP_CONFIG_PATHS"}},
}

func loadConfig() (*config, error) {
	v := newConfigViper()
	if err := readConfigSources(v); err != nil {
		return nil, err
	}

	cfg := &config{
		MySQLDSN:                      strings.TrimSpace(v.GetString("mysql.dsn")),
		MySQLReadDSN:                  strings.TrimSpace(v.GetString("mysql.read_dsn")),
		MySQLStrongReadSessionByID:    v.GetBool("mysql.strong_read.session_by_id"),
		MySQLStrongReadTokenBySHA256:  v.GetBool("mysql.strong_read.token_by_sha256"),
		RedisAddr:                     strings.TrimSpace(v.GetString("redis.addr")),
		RedisPassword:                 v.GetString("redis.password"),
		RedisDB:                       v.GetInt("redis.db"),
		RedisKeyPrefix:                strings.TrimSpace(v.GetString("redis.key_prefix")),
		RedisSentinelAddrs:            strings.TrimSpace(v.GetString("redis.sentinel_addrs")),
		RedisMasterName:               strings.TrimSpace(v.GetString("redis.master_name")),
		AppEnv:                        strings.TrimSpace(v.GetString("app.env")),
		AuditAsyncEnabled:             v.GetBool("audit.async_enabled"),
		AuditStream:                   strings.TrimSpace(v.GetString("audit.stream")),
		AuditDLQStream:                strings.TrimSpace(v.GetString("audit.dlq_stream")),
		AuditConsumerGroup:            strings.TrimSpace(v.GetString("audit.consumer_group")),
		AuditConsumerName:             strings.TrimSpace(v.GetString("audit.consumer_name")),
		AuditBatchSize:                v.GetInt("audit.batch_size"),
		AuditDedupTTL:                 v.GetDuration("audit.dedup_ttl"),
		AuditRetryTTL:                 v.GetDuration("audit.retry_ttl"),
		AuditBlockTimeout:             v.GetDuration("audit.block_timeout"),
		AuditReclaimIdle:              v.GetDuration("audit.reclaim_idle"),
		AuditReclaimInterval:          v.GetDuration("audit.reclaim_interval"),
		AuditMaxRetryCount:            v.GetInt("audit.max_retry_count"),
		SessionTTL:                    v.GetDuration("session.ttl"),
		Issuer:                        strings.TrimSpace(v.GetString("issuer")),
		TOTPIssuer:                    strings.TrimSpace(v.GetString("totp.issuer")),
		JWTKeyID:                      strings.TrimSpace(v.GetString("jwt.key_id")),
		WorkDir:                       getWorkingDir(),
		SigningKeyDir:                 strings.TrimSpace(v.GetString("signing_key.dir")),
		SigningKeyBits:                v.GetInt("signing_key.bits"),
		SigningKeyCheckInterval:       v.GetDuration("signing_key.check_interval"),
		SigningKeyRotateBefore:        v.GetDuration("signing_key.rotate_before"),
		SigningKeyRetireAfter:         v.GetDuration("signing_key.retire_after"),
		FederatedOIDCIssuer:           strings.TrimSpace(v.GetString("federated_oidc.issuer")),
		FederatedOIDCClientID:         strings.TrimSpace(v.GetString("federated_oidc.client_id")),
		FederatedOIDCClientSecret:     v.GetString("federated_oidc.client_secret"),
		FederatedOIDCRedirectURI:      strings.TrimSpace(v.GetString("federated_oidc.redirect_uri")),
		FederatedOIDCProviderName:     strings.TrimSpace(v.GetString("federated_oidc.provider_name")),
		FederatedOIDCClientAuthMethod: strings.TrimSpace(v.GetString("federated_oidc.client_auth_method")),
		FederatedOIDCUsernameClaim:    strings.TrimSpace(v.GetString("federated_oidc.username_claim")),
		FederatedOIDCDisplayNameClaim: strings.TrimSpace(v.GetString("federated_oidc.display_name_claim")),
		FederatedOIDCEmailClaim:       strings.TrimSpace(v.GetString("federated_oidc.email_claim")),
		FederatedOIDCScopes:           readStringSlice(v, "federated_oidc.scopes"),
		FederatedOIDCStateTTL:         v.GetDuration("federated_oidc.state_ttl"),
		LoginFailureWindow:            v.GetDuration("login.failure_window"),
		LoginMaxFailuresPerIP:         v.GetInt("login.max_failures_per_ip"),
		LoginMaxFailuresPerUser:       v.GetInt("login.max_failures_per_user"),
		LoginUserLockThreshold:        v.GetInt("login.user_lock_threshold"),
		LoginUserLockTTL:              v.GetDuration("login.user_lock_ttl"),
		ForceMFAEnrollment:            v.GetBool("mfa.force_enrollment"),
		PasskeyEnabled:                v.GetBool("passkey.enabled"),
		PasskeyRPID:                   strings.TrimSpace(v.GetString("passkey.rp_id")),
		PasskeyRPDisplayName:          strings.TrimSpace(v.GetString("passkey.rp_display_name")),
		PasskeyRPOrigins:              readStringSlice(v, "passkey.rp_origins"),
		TOTPSecretEncryptionKey:       strings.TrimSpace(v.GetString("totp.secret_encryption_key")),
	}

	if cfg.MySQLDSN == "" {
		cfg.MySQLDSN = buildMySQLDSN(v)
	}
	if cfg.MySQLReadDSN == "" {
		cfg.MySQLReadDSN = cfg.MySQLDSN
	}
	if cfg.RedisAddr == "" {
		cfg.RedisAddr = buildRedisAddr(v)
	}
	keyBuilder := cacheRedis.NewKeyBuilder(cfg.RedisKeyPrefix, cfg.AppEnv)
	if cfg.AuditStream == "" {
		cfg.AuditStream = keyBuilder.AuditStream()
	}
	if cfg.AuditDLQStream == "" {
		cfg.AuditDLQStream = keyBuilder.AuditDLQStream()
	}
	if cfg.TOTPSecretEncryptionKey == "" && strings.EqualFold(cfg.AppEnv, "dev") {
		cfg.TOTPSecretEncryptionKey = "ChangeThisTOTPSecretKey32Chars!!"
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func newConfigViper() *viper.Viper {
	v := viper.New()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	for _, binding := range configEnvBindings {
		args := append([]string{binding.key}, binding.envs...)
		_ = v.BindEnv(args...)
	}

	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.key_prefix", "idp")
	v.SetDefault("redis.master_name", "idp-master")
	v.SetDefault("app.env", "dev")
	v.SetDefault("audit.async_enabled", true)
	v.SetDefault("audit.consumer_group", "audit-writers")
	v.SetDefault("audit.consumer_name", hostnameOrDefault("idp-server"))
	v.SetDefault("audit.batch_size", 16)
	v.SetDefault("audit.dedup_ttl", 24*time.Hour)
	v.SetDefault("audit.retry_ttl", 24*time.Hour)
	v.SetDefault("audit.block_timeout", 2*time.Second)
	v.SetDefault("audit.reclaim_idle", 30*time.Second)
	v.SetDefault("audit.reclaim_interval", 15*time.Second)
	v.SetDefault("audit.max_retry_count", 10)
	v.SetDefault("session.ttl", 8*time.Hour)
	v.SetDefault("issuer", "http://localhost:8080")
	v.SetDefault("jwt.key_id", "kid-2026-01-rs256")
	v.SetDefault("signing_key.dir", "scripts/dev_keys")
	v.SetDefault("signing_key.bits", 2048)
	v.SetDefault("signing_key.check_interval", time.Hour)
	v.SetDefault("signing_key.rotate_before", 24*time.Hour)
	v.SetDefault("signing_key.retire_after", 24*time.Hour)
	v.SetDefault("federated_oidc.client_auth_method", "client_secret_basic")
	v.SetDefault("federated_oidc.provider_name", "OpenID Connect")
	v.SetDefault("federated_oidc.username_claim", "preferred_username")
	v.SetDefault("federated_oidc.display_name_claim", "name")
	v.SetDefault("federated_oidc.email_claim", "email")
	v.SetDefault("federated_oidc.scopes", []string{"openid", "profile", "email"})
	v.SetDefault("federated_oidc.state_ttl", 10*time.Minute)
	v.SetDefault("login.failure_window", 15*time.Minute)
	v.SetDefault("login.max_failures_per_ip", 20)
	v.SetDefault("login.max_failures_per_user", 5)
	v.SetDefault("login.user_lock_threshold", 5)
	v.SetDefault("login.user_lock_ttl", 30*time.Minute)
	v.SetDefault("mfa.force_enrollment", true)
	v.SetDefault("passkey.enabled", true)
	v.SetDefault("passkey.rp_display_name", "IDP Server")
	v.SetDefault("config.name", defaultConfigName)
	v.SetDefault("config.paths", []string{".", "./config", "/etc/idp-server"})

	return v
}

func readConfigSources(v *viper.Viper) error {
	configFile := strings.TrimSpace(v.GetString("config.file"))
	configType := strings.TrimSpace(v.GetString("config.type"))

	if configFile != "" {
		v.SetConfigFile(configFile)
		if configType != "" {
			v.SetConfigType(configType)
		}
	} else {
		configName := strings.TrimSpace(v.GetString("config.name"))
		if configName == "" {
			configName = defaultConfigName
		}
		v.SetConfigName(configName)
		if configType != "" {
			v.SetConfigType(configType)
		}
		for _, path := range resolveConfigSearchPaths(readStringSlice(v, "config.paths")) {
			if strings.TrimSpace(path) == "" {
				continue
			}
			v.AddConfigPath(strings.TrimSpace(path))
		}
	}

	if err := v.ReadInConfig(); err != nil {
		var fileLookupError viper.ConfigFileNotFoundError
		if configFile != "" || !errors.As(err, &fileLookupError) {
			return fmt.Errorf("read config: %w", err)
		}
	}

	return nil
}

func validateConfig(cfg *config) error {
	var issues []string

	if cfg == nil {
		return fmt.Errorf("missing config")
	}
	if strings.TrimSpace(cfg.MySQLDSN) == "" {
		issues = append(issues, "missing mysql configuration: set mysql.dsn or mysql.host/mysql.database/mysql.user/mysql.password")
	}
	if strings.TrimSpace(cfg.RedisAddr) == "" {
		issues = append(issues, "missing redis configuration: set redis.addr or redis.host")
	}
	if cfg.RedisDB < 0 {
		issues = append(issues, "redis.db must be >= 0")
	}
	if cfg.SessionTTL <= 0 {
		issues = append(issues, "session.ttl must be > 0")
	}
	if cfg.AuditBatchSize <= 0 {
		issues = append(issues, "audit.batch_size must be > 0")
	}
	if cfg.AuditDedupTTL <= 0 {
		issues = append(issues, "audit.dedup_ttl must be > 0")
	}
	if cfg.AuditRetryTTL <= 0 {
		issues = append(issues, "audit.retry_ttl must be > 0")
	}
	if cfg.AuditBlockTimeout <= 0 {
		issues = append(issues, "audit.block_timeout must be > 0")
	}
	if cfg.AuditReclaimIdle <= 0 {
		issues = append(issues, "audit.reclaim_idle must be > 0")
	}
	if cfg.AuditReclaimInterval <= 0 {
		issues = append(issues, "audit.reclaim_interval must be > 0")
	}
	if cfg.AuditMaxRetryCount <= 0 {
		issues = append(issues, "audit.max_retry_count must be > 0")
	}
	if cfg.SigningKeyBits < 2048 {
		issues = append(issues, "signing_key.bits must be >= 2048")
	}
	if cfg.SigningKeyCheckInterval <= 0 {
		issues = append(issues, "signing_key.check_interval must be > 0")
	}
	if cfg.SigningKeyRotateBefore <= 0 {
		issues = append(issues, "signing_key.rotate_before must be > 0")
	}
	if cfg.SigningKeyRetireAfter <= 0 {
		issues = append(issues, "signing_key.retire_after must be > 0")
	}
	if cfg.LoginFailureWindow <= 0 {
		issues = append(issues, "login.failure_window must be > 0")
	}
	if cfg.LoginMaxFailuresPerIP < 0 {
		issues = append(issues, "login.max_failures_per_ip must be >= 0")
	}
	if cfg.LoginMaxFailuresPerUser < 0 {
		issues = append(issues, "login.max_failures_per_user must be >= 0")
	}
	if cfg.LoginUserLockThreshold < 0 {
		issues = append(issues, "login.user_lock_threshold must be >= 0")
	}
	if cfg.LoginUserLockTTL <= 0 {
		issues = append(issues, "login.user_lock_ttl must be > 0")
	}
	if cfg.FederatedOIDCIssuer != "" || cfg.FederatedOIDCClientID != "" || cfg.FederatedOIDCRedirectURI != "" {
		if cfg.FederatedOIDCIssuer == "" || cfg.FederatedOIDCClientID == "" || cfg.FederatedOIDCRedirectURI == "" {
			issues = append(issues, "federated_oidc.issuer, federated_oidc.client_id, and federated_oidc.redirect_uri must be set together")
		}
	}
	if cfg.FederatedOIDCStateTTL <= 0 {
		issues = append(issues, "federated_oidc.state_ttl must be > 0")
	}
	if !strings.EqualFold(cfg.AppEnv, "dev") && strings.TrimSpace(cfg.TOTPSecretEncryptionKey) == "" {
		issues = append(issues, "totp.secret_encryption_key is required outside dev")
	}
	if err := validateURL("issuer", cfg.Issuer, true); err != nil {
		issues = append(issues, err.Error())
	}
	if cfg.FederatedOIDCIssuer != "" {
		if err := validateURL("federated_oidc.issuer", cfg.FederatedOIDCIssuer, true); err != nil {
			issues = append(issues, err.Error())
		}
	}
	if cfg.FederatedOIDCRedirectURI != "" {
		if err := validateURL("federated_oidc.redirect_uri", cfg.FederatedOIDCRedirectURI, true); err != nil {
			issues = append(issues, err.Error())
		}
	}
	for _, origin := range cfg.PasskeyRPOrigins {
		if err := validateURL("passkey.rp_origins", origin, true); err != nil {
			issues = append(issues, err.Error())
			break
		}
	}

	if len(issues) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(issues, "; "))
	}
	return nil
}

func validateURL(name, value string, requireHost bool) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := neturl.Parse(value)
	if err != nil {
		return fmt.Errorf("%s is invalid: %w", name, err)
	}
	if parsed.Scheme == "" {
		return fmt.Errorf("%s must include a URL scheme", name)
	}
	if requireHost && parsed.Host == "" {
		return fmt.Errorf("%s must include a host", name)
	}
	return nil
}

func buildMySQLDSN(v *viper.Viper) string {
	host := strings.TrimSpace(v.GetString("mysql.host"))
	database := strings.TrimSpace(v.GetString("mysql.database"))
	user := strings.TrimSpace(v.GetString("mysql.user"))
	password := v.GetString("mysql.password")
	port := strings.TrimSpace(v.GetString("mysql.port"))
	if port == "" {
		port = "3306"
	}
	if host == "" || database == "" || user == "" || password == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci",
		user,
		password,
		host,
		port,
		database,
	)
}

func buildRedisAddr(v *viper.Viper) string {
	host := strings.TrimSpace(v.GetString("redis.host"))
	port := strings.TrimSpace(v.GetString("redis.port"))
	if port == "" {
		port = "6379"
	}
	if host == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", host, port)
}

func readStringSlice(v *viper.Viper, key string) []string {
	for _, binding := range configEnvBindings {
		if binding.key != key {
			continue
		}
		for _, envName := range binding.envs {
			if raw, ok := os.LookupEnv(envName); ok {
				if strings.TrimSpace(raw) == "" {
					continue
				}
				return splitList(raw)
			}
		}
		break
	}
	values := v.GetStringSlice(key)
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

func splitList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\t' || r == ' '
	})
	if len(fields) == 0 {
		return nil
	}
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		result = append(result, field)
	}
	return result
}

func getWorkingDir() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func hostnameOrDefault(fallback string) string {
	host, err := os.Hostname()
	if err != nil {
		return fallback
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return fallback
	}
	return host
}

func resolveConfigSearchPaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	result := make([]string, 0, len(paths))
	homeDir := resolveHomeDir()
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if strings.HasPrefix(path, "~") {
			if homeDir != "" {
				suffix := strings.TrimPrefix(path, "~")
				suffix = strings.TrimLeft(suffix, `/\`)
				path = filepath.Join(homeDir, suffix)
			}
		}
		result = append(result, path)
	}
	return result
}

func resolveHomeDir() string {
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		return home
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(home)
}
