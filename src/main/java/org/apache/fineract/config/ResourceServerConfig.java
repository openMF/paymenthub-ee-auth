package org.apache.fineract.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.apache.fineract.core.service.AudienceVerifier;
import org.apache.fineract.core.service.TenantAwareHeaderFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 * Security setup, rebuilt on Spring Security 6. The old one was split over two
 * classes that no longer exist for Spring Boot 3:
 *
 * - AuthorizationServerConfig (@EnableAuthorizationServer) issued the tokens. Its
 *   endpoints are now in TokenController.
 * - ResourceServerConfig (@EnableResourceServer) protected the /api/v1 endpoints.
 *   That is this class, on the spring-boot-starter-oauth2-resource-server support.
 *
 * What is kept from the old setup:
 * - stateless sessions, csrf/cors/anonymous disabled
 * - /api/v1/** needs the ALL_FUNCTIONS authority, everything else has to be
 *   fully authenticated
 * - JWTs are signed and verified with the same RSA key pair (jwt.pem / jwt_pub.pem),
 *   the same "identity-provider" resource id check and the same per-tenant audience
 *   check (AudienceVerifier)
 * - the "authorities" claim of the token becomes the granted authorities, with no
 *   prefix (same as the old JwtAccessTokenConverter contract)
 * - /oauth/token and /oauth/token_key are open, /oauth/check_token needs
 *   authentication (old tokenKeyAccess / checkTokenAccess settings)
 */
@Configuration
@EnableWebSecurity
public class ResourceServerConfig {

    public static final String IDENTITY_PROVIDER_RESOURCE_ID = "identity-provider";

    @Autowired
    private InvalidAuthEntryPoint invalidAuthEntryPoint;

    /**
     * /oauth/token_key gets its own chain, with no resource server on it.
     *
     * It is the one path TenantAwareHeaderFilter lets through without resolving a
     * tenant. Spring Security validates a bearer token whenever one is present,
     * permitAll or not, and with no tenant in context AudienceVerifier has nothing to
     * compare the audience against. On the single chain the request would come back
     * 401 (or 500, before the null guard in AudienceVerifier) just because the caller
     * happened to send an Authorization header. The old setup did not have the
     * problem: token_key lived on the authorization-server chain, which had no
     * audience check at all.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain tokenKeySecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher(TenantAwareHeaderFilter.EXCLUDED_URL)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    /**
     * /oauth/token gets its own chain too, for the same reason as token_key above but
     * one step further on: the bearer filter validates a token whenever the caller
     * sends one, permitAll or not, and it stops the chain when that fails, so
     * TokenController never runs.
     *
     * That breaks the ordinary refresh: a client keeps its access token on every
     * request, the token expires, and the call it makes to get a new one - POST
     * /oauth/token with grant_type=refresh_token - still carries the expired one in the
     * Authorization header. On the resource-server chain that is a 401, so the request
     * that exists to recover from the expiry is the one the expiry blocks. A token for
     * another tenant, or the refresh token put in the header, fail the same way.
     *
     * The old setup did not have the problem: @EnableAuthorizationServer put
     * /oauth/token on its own chain, which had client Basic auth and no bearer filter
     * at all, so a stale Authorization header was simply ignored there.
     *
     * This chain does need the tenant, unlike the token_key one - TokenController reads
     * oauth_client_details from the tenant schema - and it gets it: TenantAwareHeaderFilter
     * is a servlet filter registered ahead of the security chains, so it runs whichever
     * one matches.
     *
     * permitAll is not a hole: the endpoint authenticates the caller itself, with Basic
     * or with client_id/client_secret in the body, exactly as
     * ClientCredentialsTokenEndpointFilter did before.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain tokenSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/oauth/token")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .anonymous(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // checkTokenAccess("isAuthenticated()") in the old config. This one
                        // stays here on purpose: it has to authenticate, so the bearer filter
                        // of this chain is what makes it work, not what gets in its way.
                        .requestMatchers("/oauth/check_token").authenticated()
                        // Spring Security also filters the ERROR dispatch, so the status a
                        // filter sets with sendError() is decided again on /error. Without
                        // this, the 400 "Invalid request!" that TenantAwareHeaderFilter sends
                        // when the Platform-TenantId header is missing came back as a 401 -
                        // the error page has no authentication, so anyRequest() below
                        // rejected it and replaced the status. Nothing is exposed: /error only
                        // renders the outcome of a request that was already handled.
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/api/v1/**").hasAuthority("ALL_FUNCTIONS")
                        .anyRequest().fullyAuthenticated())
                .oauth2ResourceServer(rs -> rs
                        .authenticationEntryPoint(invalidAuthEntryPoint)
                        .jwt(jwt -> jwt.decoder(jwtDecoder).jwtAuthenticationConverter(jwtAuthenticationConverter())));
        return http.build();
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("authorities");
        authoritiesConverter.setAuthorityPrefix("");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }

    /**
     * Decoder the resource server uses for bearer tokens. On top of the shared
     * validators it refuses refresh tokens: those are signed with the same key and
     * carry no "authorities" claim, so without this check one could be sent as a
     * bearer token and would authenticate with an empty authority list. That is enough
     * to satisfy anyRequest().fullyAuthenticated(), for the whole
     * refresh_token_validity (12 hours by default here, against 10 minutes for an
     * access token).
     */
    @Bean
    @Primary
    public JwtDecoder jwtDecoder(AudienceVerifier audienceVerifier) {
        return buildDecoder(List.of(JwtValidators.createDefault(), resourceIdValidator(), audienceVerifier,
                accessTokenOnlyValidator()));
    }

    /**
     * Decoder for /oauth/token and /oauth/check_token, which have to be able to read a
     * refresh token. Same validators as the one above, without the access-token-only
     * check. TokenController still verifies the "refresh" claim itself before
     * accepting a token for the refresh grant.
     */
    @Bean
    public JwtDecoder tokenEndpointJwtDecoder(AudienceVerifier audienceVerifier) {
        return buildDecoder(List.of(JwtValidators.createDefault(), resourceIdValidator(), audienceVerifier));
    }

    private static JwtDecoder buildDecoder(List<OAuth2TokenValidator<Jwt>> validators) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(PemUtils.readPublicKey("jwt_pub.pem")).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
        return decoder;
    }

    /**
     * Rejects a token carrying the "refresh" claim set by
     * TokenController.buildRefreshToken.
     */
    static OAuth2TokenValidator<Jwt> accessTokenOnlyValidator() {
        return jwt -> {
            if (Boolean.TRUE.equals(jwt.getClaim("refresh"))) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                        "A refresh token cannot be used as an access token", null));
            }
            return OAuth2TokenValidatorResult.success();
        };
    }

    /**
     * Replaces the resourceId(IDENTITY_PROVIDER_RESOURCE_ID) call of the old
     * ResourceServerSecurityConfigurer. The old stack checked this in
     * OAuth2AuthenticationManager, with the same rule kept here: a token is rejected
     * only if it carries an audience list that does not contain "identity-provider". A
     * token with no audience at all passes this validator, as it did before; note that
     * AudienceVerifier, next in the same chain, then rejects it because the tenant
     * schema name is missing from "aud".
     */
    static OAuth2TokenValidator<Jwt> resourceIdValidator() {
        return jwt -> {
            List<String> audiences = jwt.getAudience();
            if (audiences == null || audiences.isEmpty() || audiences.contains(IDENTITY_PROVIDER_RESOURCE_ID)) {
                return OAuth2TokenValidatorResult.success();
            }
            String message = "Token audiences " + audiences + " do not contain the resource id " + IDENTITY_PROVIDER_RESOURCE_ID;
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, message, null));
        };
    }

    /**
     * Signs the tokens TokenController issues. Replaces the JwtAccessTokenConverter
     * bean of the old stack, which read the same two PEM files through
     * spring-security-jwt.
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        RSAPublicKey publicKey = PemUtils.readPublicKey("jwt_pub.pem");
        RSAPrivateKey privateKey = PemUtils.readPrivateKey("jwt.pem");
        RSAKey key = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
    }
}
