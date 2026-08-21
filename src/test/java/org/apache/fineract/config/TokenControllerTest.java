package org.apache.fineract.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.fineract.core.service.AudienceVerifier;
import org.apache.fineract.core.service.TenantAwareUserDetailsService;
import org.apache.fineract.core.service.ThreadLocalContextUtil;
import org.apache.fineract.organisation.tenant.TenantServerConnection;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * The token endpoint, driven over HTTP.
 *
 * TokenController re-implements by hand what spring-security-oauth2 used to do, so
 * nothing outside this repository pins its behaviour any more. What is checked here is
 * the part that is easy to break without noticing and expensive to get wrong:
 *
 * - the split between 400 and 401. A client that cannot authenticate gets 401; a grant
 *   type the client is not allowed to use gets 400, because the old stack raised
 *   InvalidClientException there and only InvalidGrantException mapped to 401.
 * - the 401 body, which callers parse.
 * - the refresh grant, where every check is one this code has to make for itself:
 *   the token belongs to the client presenting it, it really is a refresh token, and
 *   the user still exists and is still enabled.
 *
 * The encoder and the decoder are the real ones from ResourceServerConfig, reading the
 * real jwt.pem, so the tokens here are the tokens the service issues. Only the
 * database and the authentication manager are stubbed.
 */
class TokenControllerTest {

    private static final String TENANT = "tn01";
    private static final String CLIENT_ID = "client";
    private static final String ALL_GRANTS = "password,refresh_token,client_credentials";

    private MockMvc mvc;
    private AuthenticationManager authenticationManager;
    private TenantAwareUserDetailsService userDetailsService;
    private JdbcTemplate jdbcTemplate;
    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;

    @BeforeEach
    void setUp() {
        // AudienceVerifier, inside the decoder, compares the "aud" claim with the tenant
        // of the request, which the tenant filter would have put here
        TenantServerConnection tenant = new TenantServerConnection();
        tenant.setSchemaName(TENANT);
        ThreadLocalContextUtil.setTenant(tenant);

        ResourceServerConfig config = new ResourceServerConfig();
        jwtEncoder = config.jwtEncoder();
        jwtDecoder = config.tokenEndpointJwtDecoder(new AudienceVerifier());

        authenticationManager = mock(AuthenticationManager.class);
        userDetailsService = mock(TenantAwareUserDetailsService.class);
        jdbcTemplate = mock(JdbcTemplate.class);

        TokenController controller = new TokenController();
        ReflectionTestUtils.setField(controller, "authenticationManager", authenticationManager);
        ReflectionTestUtils.setField(controller, "userDetailsService", userDetailsService);
        ReflectionTestUtils.setField(controller, "jwtEncoder", jwtEncoder);
        ReflectionTestUtils.setField(controller, "jwtDecoder", jwtDecoder);
        ReflectionTestUtils.setField(controller, "passwordEncoder", new BCryptPasswordEncoder());
        // set directly: @PostConstruct would build it from the routing datasource
        ReflectionTestUtils.setField(controller, "jdbcTemplate", jdbcTemplate);

        mvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @AfterEach
    void tearDown() {
        ThreadLocalContextUtil.clear();
    }

    // ---------- password grant ----------

    @Test
    void passwordGrantIssuesATokenWithTheClaimsTheOldConverterProduced() throws Exception {
        clientRowWithGrants(ALL_GRANTS);
        userAuthenticatesAs("mifos", "ALL_FUNCTIONS");

        String body = mvc.perform(passwordGrant()).andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("bearer"))
                .andExpect(jsonPath("$.scope").value("identity"))
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        Jwt accessToken = jwtDecoder.decode(new JSONObject(body).getString("access_token"));
        assertEquals("mifos", accessToken.getSubject());
        assertEquals("mifos", accessToken.getClaimAsString("user_name"));
        assertEquals(List.of("ALL_FUNCTIONS"), accessToken.getClaimAsStringList("authorities"));
        assertEquals(CLIENT_ID, accessToken.getClaimAsString("client_id"));
        assertTrue(accessToken.getAudience().contains(ResourceServerConfig.IDENTITY_PROVIDER_RESOURCE_ID));
        assertTrue(accessToken.getAudience().contains(TENANT), "the tenant has to be an audience, or no request passes AudienceVerifier");
    }

    @Test
    void theRefreshTokenIsNotUsableAsAnAccessToken() throws Exception {
        clientRowWithGrants(ALL_GRANTS);
        userAuthenticatesAs("mifos", "ALL_FUNCTIONS");

        Jwt refreshToken = jwtDecoder.decode(new JSONObject(passwordGrantBody()).getString("refresh_token"));
        // the resource server refuses this claim, see ResourceServerConfigValidatorTest
        assertEquals(Boolean.TRUE, refreshToken.getClaim("refresh"));
        assertTrue(refreshToken.getClaimAsStringList("authorities") == null,
                "a refresh token must carry no authorities");
    }

    @Test
    void badCredentialsReturn401AndTheBodyCallersParse() throws Exception {
        clientRowWithGrants(ALL_GRANTS);
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("nope"));

        mvc.perform(passwordGrant()).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("401"))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Invalid credentials"))
                .andExpect(jsonPath("$.path").value("/oauth/token"));
    }

    // ---------- client authentication, and the 400/401 split ----------

    @Test
    void aGrantTheClientMayNotUseIs400NotAuthenticationFailure() throws Exception {
        clientRowWithGrants("client_credentials");

        mvc.perform(passwordGrant()).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void anUnknownClientIs401() throws Exception {
        when(jdbcTemplate.queryForMap(anyString(), eq("ghost"))).thenThrow(new EmptyResultDataAccessException(1));

        mvc.perform(post("/oauth/token").param("grant_type", "password").param("client_id", "ghost")
                .param("username", "mifos").param("password", "password")).andExpect(status().isUnauthorized());
    }

    @Test
    void noClientAuthenticationAtAllIs401() throws Exception {
        mvc.perform(post("/oauth/token").param("grant_type", "password").param("username", "mifos")
                .param("password", "password")).andExpect(status().isUnauthorized());
    }

    @Test
    void aBasicHeaderThatIsNotBase64Is401NotBadRequest() throws Exception {
        // Base64.decode throws IllegalArgumentException, which the catch above it answers
        // with 400. It is a failed client authentication, so it has to be 401 like the
        // missing-colon case next to it.
        mvc.perform(post("/oauth/token").header("Authorization", "Basic !!!not-base64!!!")
                .param("grant_type", "password").param("username", "mifos").param("password", "password"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void theClientIdCanComeFromTheBasicHeader() throws Exception {
        clientRowWithGrants(ALL_GRANTS);
        userAuthenticatesAs("mifos", "ALL_FUNCTIONS");
        String basic = java.util.Base64.getEncoder().encodeToString((CLIENT_ID + ":").getBytes());

        mvc.perform(post("/oauth/token").header("Authorization", "Basic " + basic)
                .param("grant_type", "password").param("username", "mifos").param("password", "password"))
                .andExpect(status().isOk());
    }

    // ---------- refresh grant ----------

    @Test
    void refreshGrantReturnsTheSameRefreshTokenSoTheSessionStillEnds() throws Exception {
        clientRowWithGrants(ALL_GRANTS);
        userAuthenticatesAs("mifos", "ALL_FUNCTIONS");
        String refreshToken = new JSONObject(passwordGrantBody()).getString("refresh_token");
        when(userDetailsService.loadUserByUsername("mifos")).thenReturn(enabledUser());

        String body = mvc.perform(refreshGrant(refreshToken)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertEquals(refreshToken, new JSONObject(body).getString("refresh_token"),
                "issuing a new refresh token here would push its expiry forward at every refresh");
        Jwt reissued = jwtDecoder.decode(new JSONObject(body).getString("access_token"));
        assertEquals(List.of("ALL_FUNCTIONS"), reissued.getClaimAsStringList("authorities"));
        assertFalse(Boolean.TRUE.equals(reissued.getClaim("refresh")));
    }

    @Test
    void aRefreshTokenOfAnotherClientIsRejected() throws Exception {
        clientRowWithGrants(ALL_GRANTS);
        // the user has to exist and be enabled, otherwise the checks after this one would
        // produce the same 401 and the test would pass with the client check removed
        when(userDetailsService.loadUserByUsername("mifos")).thenReturn(enabledUser());

        mvc.perform(refreshGrant(refreshTokenFor("someone-else"))).andExpect(status().isUnauthorized());
    }

    @Test
    void anAccessTokenOfferedAsARefreshTokenIsRejected() throws Exception {
        clientRowWithGrants(ALL_GRANTS);
        userAuthenticatesAs("mifos", "ALL_FUNCTIONS");
        String accessToken = new JSONObject(passwordGrantBody()).getString("access_token");
        // as above: the user has to be there, or the refusal could come from a later check
        when(userDetailsService.loadUserByUsername("mifos")).thenReturn(enabledUser());

        mvc.perform(refreshGrant(accessToken)).andExpect(status().isUnauthorized());
    }

    @Test
    void aUserDeletedWhileHoldingARefreshTokenGets401NotAnError() throws Exception {
        clientRowWithGrants(ALL_GRANTS);
        userAuthenticatesAs("mifos", "ALL_FUNCTIONS");
        String refreshToken = new JSONObject(passwordGrantBody()).getString("refresh_token");
        // the repository query returns a plain AppUser, so an unknown user comes back null
        when(userDetailsService.loadUserByUsername("mifos")).thenReturn(null);

        mvc.perform(refreshGrant(refreshToken)).andExpect(status().isUnauthorized());
    }

    @Test
    void aDisabledUserCannotKeepMintingAccessTokens() throws Exception {
        clientRowWithGrants(ALL_GRANTS);
        userAuthenticatesAs("mifos", "ALL_FUNCTIONS");
        String refreshToken = new JSONObject(passwordGrantBody()).getString("refresh_token");
        // loadUserByUsername returns a disabled user instead of throwing
        when(userDetailsService.loadUserByUsername("mifos")).thenReturn(User.withUsername("mifos").password("x")
                .authorities("ALL_FUNCTIONS").disabled(true).build());

        mvc.perform(refreshGrant(refreshToken)).andExpect(status().isUnauthorized());
    }

    @Test
    void aRefreshTokenWithoutAGrantForItIsRejected() throws Exception {
        clientRowWithGrants("password");

        mvc.perform(refreshGrant(refreshTokenFor(CLIENT_ID))).andExpect(status().isBadRequest());
    }

    // ---------- client_credentials ----------

    @Test
    void clientCredentialsGrantHasNoRefreshTokenAndTheClientAuthorities() throws Exception {
        Map<String, Object> client = clientRowWithGrants(ALL_GRANTS);
        client.put("authorities", "SOME_FUNCTION");

        String body = mvc.perform(post("/oauth/token").param("grant_type", "client_credentials")
                .param("client_id", CLIENT_ID)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        JSONObject json = new JSONObject(body);
        assertFalse(json.has("refresh_token"), "client_credentials issues no refresh token");
        Jwt token = jwtDecoder.decode(json.getString("access_token"));
        assertEquals(List.of("SOME_FUNCTION"), token.getClaimAsStringList("authorities"));
        assertEquals(CLIENT_ID, token.getSubject());
        assertTrue(token.getClaimAsString("user_name") == null, "there is no user behind this grant");
    }

    // ---------- helpers ----------

    private Map<String, Object> clientRowWithGrants(String grants) {
        Map<String, Object> client = new LinkedHashMap<>();
        client.put("client_id", CLIENT_ID);
        client.put("client_secret", null); // as V27__oauth_changes.sql seeds it
        client.put("resource_ids", ResourceServerConfig.IDENTITY_PROVIDER_RESOURCE_ID + "," + TENANT);
        client.put("scope", "identity");
        client.put("authorized_grant_types", grants);
        client.put("access_token_validity", 600);
        client.put("refresh_token_validity", 43200);
        when(jdbcTemplate.queryForMap(anyString(), eq(CLIENT_ID))).thenReturn(client);
        return client;
    }

    private void userAuthenticatesAs(String username, String authority) {
        when(authenticationManager.authenticate(any())).thenReturn(new UsernamePasswordAuthenticationToken(username,
                null, List.of(new SimpleGrantedAuthority(authority))));
    }

    private UserDetails enabledUser() {
        return User.withUsername("mifos").password("x").authorities("ALL_FUNCTIONS").build();
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder passwordGrant() {
        return post("/oauth/token").param("grant_type", "password").param("client_id", CLIENT_ID)
                .param("username", "mifos").param("password", "password");
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder refreshGrant(String token) {
        return post("/oauth/token").param("grant_type", "refresh_token").param("client_id", CLIENT_ID)
                .param("refresh_token", token);
    }

    private String passwordGrantBody() throws Exception {
        return mvc.perform(passwordGrant()).andReturn().getResponse().getContentAsString();
    }

    /** A refresh token this service would accept, but issued to the given client. */
    private String refreshTokenFor(String clientId) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder().subject("mifos")
                .audience(List.of(ResourceServerConfig.IDENTITY_PROVIDER_RESOURCE_ID, TENANT))
                .issuedAt(now).expiresAt(now.plusSeconds(600)).id(UUID.randomUUID().toString())
                .claim("client_id", clientId).claim("user_name", "mifos").claim("refresh", true).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims))
                .getTokenValue();
    }
}
