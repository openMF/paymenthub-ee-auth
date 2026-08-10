package org.apache.fineract.config;

import org.apache.fineract.core.service.RoutingDataSource;
import org.apache.fineract.core.service.TenantAwareUserDetailsService;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Replacement for the /oauth/token, /oauth/token_key and /oauth/check_token
 * endpoints of the discontinued Spring
 * Security OAuth2 authorization server (spring-security-oauth2 2.4.1). That
 * stack does not exist for Spring Boot 3, and its successor
 * (spring-authorization-server) dropped the password grant that the
 * operations web console uses to log in. So the endpoint is re-implemented
 * here with the same external contract:
 *
 * - grant_type=password           username/password checked against the tenant DB users
 * - grant_type=refresh_token      re-issues tokens from a valid refresh token
 * - grant_type=client_credentials for machine clients
 * - clients and their token validities still come from the oauth_client_details
 *   table of the current tenant (same rows the old JdbcClientDetailsService read)
 * - tokens are the same RSA-signed JWTs (jwt.pem), with the same claims the old
 *   JwtAccessTokenConverter produced (user_name, authorities, aud, scope, jti)
 * - the JSON response body and the 401 error body keep the old shape (the 401
 *   replicates what the deleted AuthExceptionTranslator used to return)
 *
 * Same replacement already made in ph-ee-operations-app, which validates the tokens
 * this service issues, so the two have to agree claim by claim.
 */
@RestController
public class TokenController {

    // DefaultTokenServices defaults from the old stack
    private static final long DEFAULT_ACCESS_TOKEN_VALIDITY_SECONDS = 60 * 60 * 12;
    private static final long DEFAULT_REFRESH_TOKEN_VALIDITY_SECONDS = 60L * 60 * 24 * 30;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TenantAwareUserDetailsService userDetailsService;

    @Autowired
    private JwtEncoder jwtEncoder;

    // the decoder without the access-token-only validator: this endpoint has to be
    // able to read a refresh token (see ResourceServerConfig)
    @Autowired
    @Qualifier("tokenEndpointJwtDecoder")
    private JwtDecoder jwtDecoder;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RoutingDataSource routingDataSource;

    private JdbcTemplate jdbcTemplate;

    @PostConstruct
    void initJdbcTemplate() {
        // JdbcTemplate is thread safe, one instance is enough for every request
        this.jdbcTemplate = new JdbcTemplate(routingDataSource);
    }

    @PostMapping(value = "/oauth/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> token(@RequestParam Map<String, String> params,
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader) {
        try {
            String grantType = params.get("grant_type");
            String[] clientCredentials = resolveClientCredentials(params, authorizationHeader);
            Map<String, Object> client = loadClient(clientCredentials[0]);
            checkClientSecret(client, clientCredentials[1]);
            checkGrantAllowed(client, grantType);

            if ("password".equals(grantType)) {
                Authentication user = authenticationManager
                        .authenticate(new UsernamePasswordAuthenticationToken(params.get("username"), params.get("password")));
                List<String> authorities = toAuthorityNames(user.getAuthorities());
                return tokenResponse(client, buildAccessToken(client, user.getName(), authorities, true),
                        buildRefreshToken(client, user.getName()).getTokenValue());
            }

            if ("refresh_token".equals(grantType)) {
                Jwt refreshToken = decodeRefreshToken(params.get("refresh_token"));
                // the refresh token has to belong to the client presenting it, like the old
                // DefaultTokenServices.refreshAccessToken checked ("Wrong client for this
                // refresh token"). Without this a client could redeem another client's
                // refresh token and get an access token minted with its own resource_ids,
                // scope and validity. Cross-tenant redemption is already blocked by
                // AudienceVerifier; this closes it between clients of the same tenant.
                String tokenClientId = refreshToken.getClaimAsString("client_id");
                if (tokenClientId == null || !tokenClientId.equals(client.get("client_id"))) {
                    throw new BadCredentialsException("Wrong client for this refresh token");
                }
                String username = refreshToken.getClaimAsString("user_name");
                UserDetails user = userDetailsService.loadUserByUsername(username);
                // AppUserRepository.findAppUserByName is a @Query returning a plain AppUser,
                // so an unknown username comes back as null instead of raising
                // UsernameNotFoundException. That happens for real: a user deleted through
                // DELETE /api/v1/user/{userId} while still holding a refresh token. Without
                // this check the line below throws NullPointerException, which is not an
                // AuthenticationException, so the caller would get 400 invalid_request and a
                // stack trace in the log instead of the usual 401.
                if (user == null) {
                    throw new BadCredentialsException("Unknown user: " + username);
                }
                // loadUserByUsername returns a disabled or locked user instead of throwing,
                // so without this a user disabled in m_appuser keeps minting access tokens
                // for the rest of the refresh token's life (12 hours with the
                // refresh_token_validity this repo seeds, 30 days if the column is NULL).
                // The old DefaultTokenServices ran the same check through a
                // UserDetailsChecker. The exceptions it throws are AuthenticationException,
                // so they come out as the usual 401 body.
                new AccountStatusUserDetailsChecker().check(user);
                List<String> authorities = toAuthorityNames(user.getAuthorities());
                // the refresh token that came in is handed back unchanged, like the old
                // DefaultTokenServices did (reuseRefreshToken is true by default). Issuing a
                // new one here would push its expiry forward at every refresh, so a session
                // could be kept alive for ever instead of ending after refresh_token_validity.
                return tokenResponse(client, buildAccessToken(client, username, authorities, true),
                        refreshToken.getTokenValue());
            }

            if ("client_credentials".equals(grantType)) {
                List<String> authorities = commaSeparated(client.get("authorities"));
                return tokenResponse(client, buildAccessToken(client, (String) client.get("client_id"), authorities, false), null);
            }

            return errorResponse(HttpStatus.BAD_REQUEST, "Unsupported grant type: " + grantType);
        } catch (IllegalArgumentException e) {
            // A bad request, not a server problem: /oauth/token is permitAll, so letting
            // this reach the generic handler below would let any caller fill the log with
            // ERROR-level stack traces by sending an unknown grant_type. The old
            // AuthExceptionTranslator turned the same case into a 400 and logged nothing.
            logger.debug("Rejected token request: {}", e.getMessage());
            return errorResponse(HttpStatus.BAD_REQUEST, "invalid_request");
        } catch (AuthenticationException e) {
            // same body the old AuthExceptionTranslator produced for InvalidGrantException
            JSONObject body = new JSONObject();
            body.put("timestamp", new Date().toInstant().toEpochMilli());
            body.put("status", "401");
            body.put("error", "Unauthorized");
            body.put("message", "Invalid credentials");
            body.put("path", "/oauth/token");
            return new ResponseEntity<>(body.toString(), HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            // /oauth/token is permitAll, so the message must not carry internals
            // (driver and SQL messages used to end up in the response body here)
            logger.error("Token request failed", e);
            return errorResponse(HttpStatus.BAD_REQUEST, "invalid_request");
        }
    }

    /**
     * Same as the old TokenKeyEndpoint: publishes the public half of the signing
     * key so other services can verify the JWTs themselves. It was permitAll in
     * the old AuthorizationServerConfig and stays open here.
     */
    @GetMapping(value = "/oauth/token_key", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> tokenKey() {
        JSONObject body = new JSONObject();
        body.put("alg", "SHA256withRSA");
        body.put("value", PemUtils.readPublicKeyPem("jwt_pub.pem"));
        return ResponseEntity.ok(body.toString());
    }

    /**
     * Same as the old CheckTokenEndpoint: returns the claims of a token, or 400
     * with an invalid_token error. It required authentication before
     * (checkTokenAccess("isAuthenticated()")) and still does, through the
     * .requestMatchers("/oauth/check_token").authenticated() rule in
     * ResourceServerConfig.
     *
     * It decodes with tokenEndpointJwtDecoder, so it also reports a refresh token as
     * valid. That is on purpose: the old CheckTokenEndpoint had one converter for both
     * kinds of token and did the same. Callers that need to know which one they hold
     * can read the "refresh" claim from the response.
     */
    @PostMapping(value = "/oauth/check_token", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> checkToken(@RequestParam("token") String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            Map<String, Object> claims = new LinkedHashMap<>(jwt.getClaims());
            // the old endpoint returned iat/exp as epoch seconds, Jwt holds them as Instant
            for (Map.Entry<String, Object> claim : claims.entrySet()) {
                if (claim.getValue() instanceof Instant) {
                    claim.setValue(((Instant) claim.getValue()).getEpochSecond());
                }
            }
            return ResponseEntity.ok(new JSONObject(claims).toString());
        } catch (JwtException e) {
            JSONObject body = new JSONObject();
            body.put("error", "invalid_token");
            body.put("error_description", e.getMessage());
            return new ResponseEntity<>(body.toString(), HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * Basic header first, client_id/client_secret parameters after.
     *
     * The parameter form is a deliberate difference from the old stack, not an
     * oversight. The old AuthorizationServerConfig never called
     * allowFormAuthenticationForClients(), so /oauth/token sat behind
     * BasicAuthenticationFilter and a client_id sent as a parameter was answered with
     * 401. It is accepted here because ph-ee-operations-app, which carries the same
     * replacement, accepts it, and because RFC 6749 allows it for a client with no
     * secret - which is what V27__oauth_changes.sql seeds. It widens nothing on its
     * own: the secret is checked the same way whichever way it arrives.
     *
     * One consequence had to be handled: a secret can now be a request parameter, and
     * PlatformRequestLog logs the parameter map, so client_secret is dropped there.
     */
    private String[] resolveClientCredentials(Map<String, String> params, String authorizationHeader) {
        // Locale.ROOT: in a Turkish default locale "BASIC " lowercases to "bas0131c "
        // and no Basic header would ever be recognised
        if (authorizationHeader != null && authorizationHeader.toLowerCase(Locale.ROOT).startsWith("basic ")) {
            byte[] credentials;
            try {
                credentials = Base64.getDecoder().decode(authorizationHeader.substring(6));
            } catch (IllegalArgumentException e) {
                // decode() throws IllegalArgumentException on anything that is not base64,
                // which the caller of this method turns into 400 invalid_request. A broken
                // Basic header is a failed client authentication: BasicAuthenticationFilter
                // answered 401 for it before, and the missing-colon case two lines below
                // already does, so it has to be an AuthenticationException here too.
                throw new BadCredentialsException("Malformed Basic authentication header", e);
            }
            String decoded = new String(credentials, StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            if (separator < 0) {
                throw new BadCredentialsException("Malformed Basic authentication header");
            }
            return new String[] { decoded.substring(0, separator), decoded.substring(separator + 1) };
        }
        if (params.containsKey("client_id")) {
            return new String[] { params.get("client_id"), params.getOrDefault("client_secret", "") };
        }
        throw new BadCredentialsException("Missing client authentication");
    }

    private Map<String, Object> loadClient(String clientId) {
        try {
            return jdbcTemplate.queryForMap("SELECT * FROM oauth_client_details WHERE client_id = ?", clientId);
        } catch (EmptyResultDataAccessException e) {
            throw new BadCredentialsException("Unknown client: " + clientId);
        }
    }

    private void checkClientSecret(Map<String, Object> client, String providedSecret) {
        String stored = (String) client.get("client_secret");
        String provided = providedSecret == null ? "" : providedSecret;
        if (stored == null || stored.isEmpty()) {
            return; // public client with no secret
        }
        // both branches are needed: V27__oauth_changes.sql seeds the "client" row with no
        // secret at all (handled above), and secrets added to the table later may be
        // plaintext or bcrypt, as the old JdbcClientDetailsService also accepted.
        // MessageDigest.isEqual so the comparison is constant time.
        boolean matches = stored.startsWith("$2") ? passwordEncoder.matches(provided, stored)
                : MessageDigest.isEqual(stored.getBytes(StandardCharsets.UTF_8), provided.getBytes(StandardCharsets.UTF_8));
        if (!matches) {
            throw new BadCredentialsException("Bad client credentials");
        }
    }

    /**
     * Not an AuthenticationException on purpose, so this comes out as 400 and not 401.
     * The old stack split the two the same way: a client that could not authenticate got
     * 401 from the endpoint filter, while a grant type the client is not allowed to use
     * raised InvalidClientException, which AuthExceptionTranslator turned into 400
     * because only InvalidGrantException mapped to 401.
     */
    private void checkGrantAllowed(Map<String, Object> client, String grantType) {
        List<String> allowed = commaSeparated(client.get("authorized_grant_types"));
        if (grantType == null || !allowed.contains(grantType)) {
            throw new IllegalArgumentException("Grant type " + grantType + " not allowed for this client");
        }
    }

    private Jwt decodeRefreshToken(String token) {
        if (token == null) {
            throw new BadCredentialsException("Missing refresh_token");
        }
        try {
            Jwt jwt = jwtDecoder.decode(token);
            if (!Boolean.TRUE.equals(jwt.getClaim("refresh"))) {
                throw new BadCredentialsException("Not a refresh token");
            }
            return jwt;
        } catch (JwtException e) {
            throw new BadCredentialsException("Invalid refresh token", e);
        }
    }

    private Jwt buildAccessToken(Map<String, Object> client, String subject, List<String> authorities, boolean userToken) {
        Instant now = Instant.now();
        long validity = intColumn(client, "access_token_validity", DEFAULT_ACCESS_TOKEN_VALIDITY_SECONDS);
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .subject(subject)
                .audience(commaSeparated(client.get("resource_ids")))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(validity))
                .id(UUID.randomUUID().toString())
                .claim("client_id", client.get("client_id"))
                .claim("scope", commaSeparated(client.get("scope")))
                .claim("authorities", authorities);
        if (userToken) {
            claims.claim("user_name", subject);
        }
        return jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims.build()));
    }

    private Jwt buildRefreshToken(Map<String, Object> client, String username) {
        Instant now = Instant.now();
        long validity = intColumn(client, "refresh_token_validity", DEFAULT_REFRESH_TOKEN_VALIDITY_SECONDS);
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(username)
                .audience(commaSeparated(client.get("resource_ids")))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(validity))
                .id(UUID.randomUUID().toString())
                .claim("client_id", client.get("client_id"))
                .claim("user_name", username)
                .claim("refresh", true)
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims));
    }

    private ResponseEntity<String> tokenResponse(Map<String, Object> client, Jwt accessToken, String refreshToken) {
        JSONObject body = new JSONObject();
        body.put("access_token", accessToken.getTokenValue());
        body.put("token_type", "bearer");
        if (refreshToken != null) {
            body.put("refresh_token", refreshToken);
        }
        body.put("expires_in", accessToken.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond());
        body.put("scope", String.join(" ", commaSeparated(client.get("scope"))));
        body.put("jti", accessToken.getId());
        return ResponseEntity.ok(body.toString());
    }

    private ResponseEntity<String> errorResponse(HttpStatus status, String message) {
        JSONObject body = new JSONObject();
        body.put("error", message);
        return new ResponseEntity<>(body.toString(), status);
    }

    private static List<String> toAuthorityNames(Iterable<? extends GrantedAuthority> authorities) {
        List<String> names = new ArrayList<>();
        for (GrantedAuthority authority : authorities) {
            names.add(authority.getAuthority());
        }
        return names;
    }

    /**
     * The oauth_client_details columns are comma separated lists. Entries are not
     * trimmed, matching the comma-delimited parsing the old JdbcClientDetailsService
     * used: a row written as "password, refresh_token" is rejected by both the old
     * code and this one. Worth fixing, but outside a migration that has to keep
     * behaviour identical.
     */
    private static List<String> commaSeparated(Object value) {
        if (value == null || value.toString().isEmpty()) {
            return List.of();
        }
        return Arrays.asList(value.toString().split(","));
    }

    private static long intColumn(Map<String, Object> client, String column, long defaultValue) {
        Object value = client.get(column);
        return value == null ? defaultValue : ((Number) value).longValue();
    }
}
