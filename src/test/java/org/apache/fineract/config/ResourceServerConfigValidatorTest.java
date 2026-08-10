package org.apache.fineract.config;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * The two token validators plugged into the JwtDecoder in ResourceServerConfig.
 * Both are pure functions of a Jwt, so they need no Spring context and no database.
 *
 * accessTokenOnlyValidator is the one worth pinning: refresh tokens are signed with
 * the same key as access tokens and carry no "authorities" claim, so before it existed
 * a refresh token sent as a bearer token authenticated with an empty authority list -
 * enough for anyRequest().fullyAuthenticated() on any endpoint with no explicit rule,
 * for the whole refresh-token lifetime.
 */
class ResourceServerConfigValidatorTest {

    private static Jwt jwt(List<String> audience, Boolean refreshClaim) {
        Jwt.Builder builder = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("mifos")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60));
        if (audience != null) {
            builder.audience(audience);
        }
        if (refreshClaim != null) {
            builder.claim("refresh", refreshClaim);
        }
        return builder.build();
    }

    @Test
    void accessTokenOnlyValidatorRejectsARefreshToken() {
        assertTrue(ResourceServerConfig.accessTokenOnlyValidator().validate(jwt(null, true)).hasErrors());
    }

    @Test
    void accessTokenOnlyValidatorAcceptsAnAccessToken() {
        assertFalse(ResourceServerConfig.accessTokenOnlyValidator().validate(jwt(null, null)).hasErrors());
    }

    @Test
    void accessTokenOnlyValidatorAcceptsRefreshFalse() {
        // only the claim set to true marks a refresh token; anything else is an access token
        assertFalse(ResourceServerConfig.accessTokenOnlyValidator().validate(jwt(null, false)).hasErrors());
    }

    @Test
    void resourceIdValidatorAcceptsTheIdentityProviderAudience() {
        assertFalse(ResourceServerConfig.resourceIdValidator()
                .validate(jwt(List.of(ResourceServerConfig.IDENTITY_PROVIDER_RESOURCE_ID, "tn01"), null)).hasErrors());
    }

    @Test
    void resourceIdValidatorRejectsAnotherAudience() {
        assertTrue(ResourceServerConfig.resourceIdValidator().validate(jwt(List.of("somebody-else"), null)).hasErrors());
    }

    @Test
    void resourceIdValidatorLetsATokenWithNoAudienceThrough() {
        // same as the old resourceId() check: no audience passes here, and AudienceVerifier
        // is the one that then rejects it for not naming the tenant schema
        assertFalse(ResourceServerConfig.resourceIdValidator().validate(jwt(null, null)).hasErrors());
    }
}
