package org.apache.fineract.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

/**
 * PemUtils replaces the PEM parsing that spring-security-jwt used to do, and every
 * token this service issues depends on it. jwt.pem is in the old PKCS#1 format, which
 * the JDK cannot read directly, so PemUtils re-wraps it into PKCS#8 by hand - the part
 * most likely to break silently.
 *
 * The round trip below is the real check: it signs a token with the private key and
 * verifies it with the public one, exactly as TokenController and the resource server
 * do. If the two files did not belong to the same key pair, or the PKCS#8 wrapping were
 * wrong, this would fail. No Spring context and no database needed.
 */
class PemUtilsTest {

    @Test
    void signsWithTheKeyPairFromTheClasspathAndVerifiesItBack() {
        RSAPublicKey publicKey = PemUtils.readPublicKey("jwt_pub.pem");
        RSAPrivateKey privateKey = PemUtils.readPrivateKey("jwt.pem");
        RSAKey key = new RSAKey.Builder(publicKey).privateKey(privateKey).build();

        Instant now = Instant.now();
        Jwt signed = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)))
                .encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(),
                        JwtClaimsSet.builder()
                                .subject("mifos")
                                .audience(java.util.List.of("identity-provider", "tn01"))
                                .issuedAt(now)
                                .expiresAt(now.plusSeconds(60))
                                .build()));

        Jwt verified = NimbusJwtDecoder.withPublicKey(publicKey).build().decode(signed.getTokenValue());

        assertEquals("mifos", verified.getSubject());
        assertTrue(verified.getAudience().contains("identity-provider"));
    }

    @Test
    void publishesThePublicKeyInPemForm() {
        // this exact string is what /oauth/token_key returns, so other services can
        // verify the tokens themselves
        String pem = PemUtils.readPublicKeyPem("jwt_pub.pem");
        assertTrue(pem.startsWith("-----BEGIN PUBLIC KEY-----"));
        assertTrue(pem.endsWith("-----END PUBLIC KEY-----"));
    }
}
