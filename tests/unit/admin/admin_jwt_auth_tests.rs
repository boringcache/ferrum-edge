//! Tests for admin JWT authentication

use chrono::{Duration, Utc};
use ferrum_edge::admin::jwt_auth::{AdminClaims, AdminRole, JwtConfig, JwtError, JwtManager};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;

fn test_jwt_config() -> JwtConfig {
    JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    }
}

fn encode_json_claims(claims: serde_json::Value, secret: &str, algorithm: Algorithm) -> String {
    let header = Header::new(algorithm);
    let key = EncodingKey::from_secret(secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

#[test]
fn test_jwt_verification() {
    let manager = JwtManager::new(test_jwt_config());

    // Create a test token manually (as a client would)
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(1800)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({"role": "admin"}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    // Verify token
    let token_data = manager.verify_token(&token).unwrap();

    assert_eq!(token_data.claims.iss, "test-issuer");
    assert_eq!(token_data.claims.sub, "admin-user");
    assert_eq!(token_data.claims.additional["role"], "admin");
}

#[test]
fn test_authorization_header_extraction_is_case_insensitive_and_strict() {
    assert_eq!(
        JwtManager::extract_token_from_header("Bearer abc.def"),
        Some("abc.def".to_string())
    );
    assert_eq!(
        JwtManager::extract_token_from_header("bearer abc.def"),
        Some("abc.def".to_string())
    );
    assert_eq!(
        JwtManager::extract_token_from_header("BEARER   abc.def"),
        Some("abc.def".to_string())
    );
    assert_eq!(JwtManager::extract_token_from_header("Bearer "), None);
    assert_eq!(JwtManager::extract_token_from_header("Bearer"), None);
    assert_eq!(JwtManager::extract_token_from_header("Basic abc.def"), None);
    assert_eq!(
        JwtManager::extract_token_from_header("Bearer abc.def extra"),
        None
    );
}

#[test]
fn test_verify_request_maps_header_failures_and_accepts_lowercase_bearer() {
    let manager = JwtManager::new(test_jwt_config());
    let now = Utc::now();
    let claims = json!({
        "iss": "test-issuer",
        "sub": "admin-user",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + Duration::seconds(1800)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "role": "admin",
    });
    let token = encode_json_claims(claims, "test-secret", Algorithm::HS256);
    let lowercase_header = format!("bearer {token}");

    assert!(manager.verify_request(Some(&lowercase_header)).is_ok());
    assert!(matches!(
        manager.verify_request(None),
        Err(JwtError::MissingHeader)
    ));
    assert!(matches!(
        manager.verify_request(Some("Basic abc.def")),
        Err(JwtError::InvalidHeaderFormat)
    ));
    assert!(matches!(
        manager.verify_request(Some("Bearer ")),
        Err(JwtError::InvalidHeaderFormat)
    ));
    assert!(matches!(
        manager.verify_request(Some("Bearer abc.def extra")),
        Err(JwtError::InvalidHeaderFormat)
    ));
    assert!(matches!(
        manager.verify_request(Some("Bearer not-a-jwt")),
        Err(JwtError::VerificationFailed(_))
    ));
}

#[test]
fn test_jwt_required_claims_are_enforced() {
    let manager = JwtManager::new(test_jwt_config());
    let now = Utc::now();
    let claims_without_jti = json!({
        "iss": "test-issuer",
        "sub": "admin-user",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + Duration::seconds(1800)).timestamp(),
        "role": "admin",
    });
    let token = encode_json_claims(claims_without_jti, "test-secret", Algorithm::HS256);

    assert!(
        manager.verify_token(&token).is_err(),
        "tokens missing required registered claims must be rejected"
    );
}

#[test]
fn test_jwt_not_before_and_algorithm_are_enforced() {
    let manager = JwtManager::new(test_jwt_config());
    let now = Utc::now();
    let future_nbf_claims = json!({
        "iss": "test-issuer",
        "sub": "admin-user",
        "iat": now.timestamp(),
        "nbf": (now + Duration::hours(1)).timestamp(),
        "exp": (now + Duration::hours(2)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "role": "admin",
    });
    let future_nbf_token = encode_json_claims(future_nbf_claims, "test-secret", Algorithm::HS256);

    assert!(
        manager.verify_token(&future_nbf_token).is_err(),
        "tokens before their nbf time must be rejected"
    );

    let wrong_algorithm_claims = json!({
        "iss": "test-issuer",
        "sub": "admin-user",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + Duration::seconds(1800)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "role": "admin",
    });
    let wrong_algorithm_token =
        encode_json_claims(wrong_algorithm_claims, "test-secret", Algorithm::HS384);

    assert!(
        manager.verify_token(&wrong_algorithm_token).is_err(),
        "tokens signed with an unexpected algorithm must be rejected"
    );
}

#[test]
fn test_admin_role_claim_parses_and_requires_explicit_role() {
    let now = Utc::now();
    let mut claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(1800)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({"role": "operator"}),
    };
    assert_eq!(claims.admin_role().unwrap(), AdminRole::Operator);

    claims.additional = json!({});
    assert!(
        claims.admin_role().is_err(),
        "missing role claims must not fail open as admin"
    );

    claims.additional = json!({"role": null});
    assert!(
        claims.admin_role().is_err(),
        "explicit null role claims must not fail open as admin"
    );
}

#[test]
fn test_admin_role_claim_rejects_unknown_role() {
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(1800)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({"role": "root"}),
    };
    assert!(claims.admin_role().is_err());
}

#[test]
fn test_jwt_invalid_issuer() {
    let config1 = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "issuer-1".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let config2 = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "issuer-2".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let _manager1 = JwtManager::new(config1);
    let manager2 = JwtManager::new(config2);

    // Create token with issuer-1
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "issuer-1".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(1800)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    // Try to verify with issuer-2 (should fail)
    let result = manager2.verify_token(&token);
    assert!(result.is_err());
}

#[test]
fn test_jwt_expired_token() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    // Create expired token (expired 10 minutes ago)
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: (now - Duration::minutes(10)).timestamp(),
        nbf: (now - Duration::minutes(10)).timestamp(),
        exp: (now - Duration::minutes(5)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    // Should fail verification
    let result = manager.verify_token(&token);
    assert!(result.is_err(), "Expired token should fail verification");
}

#[test]
fn test_jwt_negative_ttl_rejected() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    // Create a token where iat > exp (negative TTL)
    // Token is still not expired (exp is in the future), but iat is even further in the future.
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: (now + Duration::hours(2)).timestamp(), // issued "in the future"
        nbf: now.timestamp(),
        exp: (now + Duration::hours(1)).timestamp(), // expires before iat
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_err(),
        "Token with negative TTL (iat > exp) should be rejected"
    );
}

#[test]
fn test_jwt_zero_ttl_rejected() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    // Create a token where iat == exp (zero TTL)
    let now = Utc::now();
    let exp_time = (now + Duration::hours(1)).timestamp();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: exp_time, // same as exp
        nbf: now.timestamp(),
        exp: exp_time,
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_err(),
        "Token with zero TTL (iat == exp) should be rejected"
    );
}

#[test]
fn test_jwt_valid_ttl_within_max() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 7200,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(3600)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_ok(),
        "Token with positive TTL within max should be accepted"
    );
}

#[test]
fn test_jwt_ttl_exceeds_max_rejected() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 1800, // 30 min max
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(3600)).timestamp(), // 1 hour > 30 min max
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_err(),
        "Token with TTL exceeding max_ttl_seconds should be rejected"
    );
}

#[test]
fn test_jwt_future_iat_within_cap_rejected() {
    // The bypass from the issue: shift `iat` and `exp` far into the future
    // while keeping `exp - iat` within the configured maximum and `nbf` at
    // the current time. The nominal TTL check alone accepts this token even
    // though it remains usable for years.
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: (now + Duration::days(3650)).timestamp(), // ~10 years in the future
        nbf: now.timestamp(),                          // immediately usable
        exp: (now + Duration::days(3650) + Duration::seconds(3600)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_err(),
        "Token with a future-shifted iat must be rejected even when exp - iat is within the cap"
    );
}

#[test]
fn test_jwt_future_iat_beyond_clock_skew_rejected() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    // jsonwebtoken's default leeway is 60 seconds; an iat further in the
    // future than that skew must be rejected.
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: (now + Duration::seconds(600)).timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(600 + 1800)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_err(),
        "Token with iat beyond the accepted clock skew should be rejected"
    );
}

#[test]
fn test_jwt_iat_within_clock_skew_accepted() {
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    // A slightly future iat from a skewed-but-honest issuer clock remains
    // acceptable (jsonwebtoken's default leeway is 60 seconds).
    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: (now + Duration::seconds(30)).timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(30 + 1800)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_ok(),
        "Token with iat within the accepted clock skew should be accepted: {:?}",
        result.err()
    );
}

#[test]
fn test_jwt_zero_max_ttl_disables_cap() {
    // `0` is the documented disable sentinel: the lifetime cap is skipped
    // entirely, so even a very long-lived (but unexpired) token verifies.
    let config = JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: None,
        max_ttl_seconds: 0,
        algorithm: Algorithm::HS256,
    };

    let manager = JwtManager::new(config);

    let now = Utc::now();
    let claims = AdminClaims {
        iss: "test-issuer".to_string(),
        sub: "admin-user".to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: (now + Duration::days(365)).timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        additional: json!({}),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret("test-secret".as_bytes());
    let token = encode(&header, &claims, &key).unwrap();

    let result = manager.verify_token(&token);
    assert!(
        result.is_ok(),
        "max_ttl_seconds = 0 is the documented disable sentinel and must skip the cap: {:?}",
        result.err()
    );
}

// ── Optional audience (`aud`) enforcement ─────────────────────────────

fn config_with_audience(audience: Option<&str>) -> JwtConfig {
    JwtConfig {
        secret: "test-secret".to_string(),
        issuer: "test-issuer".to_string(),
        audience: audience.map(str::to_string),
        max_ttl_seconds: 3600,
        algorithm: Algorithm::HS256,
    }
}

fn admin_claims_json(aud: Option<&str>) -> serde_json::Value {
    let now = Utc::now();
    let mut claims = json!({
        "iss": "test-issuer",
        "sub": "admin-user",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + Duration::seconds(1800)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
        "role": "admin",
    });
    if let Some(aud) = aud {
        claims["aud"] = json!(aud);
    }
    claims
}

#[test]
fn test_audience_match_is_accepted() {
    let manager = JwtManager::new(config_with_audience(Some("ferrum-admin")));
    let token = encode_json_claims(
        admin_claims_json(Some("ferrum-admin")),
        "test-secret",
        Algorithm::HS256,
    );
    let token_data = manager
        .verify_token(&token)
        .expect("token with matching aud must be accepted");
    assert_eq!(token_data.claims.sub, "admin-user");
}

#[test]
fn test_audience_mismatch_is_rejected() {
    let manager = JwtManager::new(config_with_audience(Some("ferrum-admin")));
    let token = encode_json_claims(
        admin_claims_json(Some("some-other-service")),
        "test-secret",
        Algorithm::HS256,
    );
    assert!(
        manager.verify_token(&token).is_err(),
        "token whose aud does not match the configured audience must be rejected"
    );
}

#[test]
fn test_audience_required_when_configured_rejects_missing_aud() {
    let manager = JwtManager::new(config_with_audience(Some("ferrum-admin")));
    let token = encode_json_claims(admin_claims_json(None), "test-secret", Algorithm::HS256);
    assert!(
        manager.verify_token(&token).is_err(),
        "when an audience is configured, a token that omits aud must be rejected"
    );
}

#[test]
fn test_audience_unset_does_not_require_aud() {
    // Default (audience: None): behavior is unchanged — a token that carries no
    // aud claim is accepted, so operators who never configure an audience are
    // unaffected.
    let manager = JwtManager::new(config_with_audience(None));
    let token = encode_json_claims(admin_claims_json(None), "test-secret", Algorithm::HS256);
    manager
        .verify_token(&token)
        .expect("with no audience configured, a token without aud must be accepted");
}

#[test]
fn test_audience_unset_rejects_aud_bearing_token() {
    // Default (audience: None): jsonwebtoken's strict `validate_aud = true`
    // default is deliberately kept. A token that CARRIES an `aud` claim is
    // rejected because no acceptable audience is configured (RFC 7519 §4.1.3).
    // This blocks cross-service token replay under HS256 secret reuse; it is
    // the pre-existing behavior, pinned here so it is never loosened silently.
    // Operators whose minter stamps `aud` must set FERRUM_ADMIN_JWT_AUDIENCE.
    let manager = JwtManager::new(config_with_audience(None));
    let token = encode_json_claims(
        admin_claims_json(Some("some-other-service")),
        "test-secret",
        Algorithm::HS256,
    );
    assert!(
        manager.verify_token(&token).is_err(),
        "with no audience configured, a token carrying aud must be rejected (strict RFC 7519 handling)"
    );
}
