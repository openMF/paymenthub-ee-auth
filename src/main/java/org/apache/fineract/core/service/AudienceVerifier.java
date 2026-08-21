/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.fineract.core.service;

import org.apache.fineract.organisation.tenant.TenantServerConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Same check as before, new interface: the token's "aud" list must contain the
 * schema name of the tenant the request is for. The old JwtClaimsSetVerifier
 * interface belonged to the discontinued Spring Security OAuth2 stack; in
 * Spring Security 6 the same hook is an OAuth2TokenValidator plugged into the
 * JwtDecoder (see ResourceServerConfig).
 */
@Component
public class AudienceVerifier implements OAuth2TokenValidator<Jwt> {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        TenantServerConnection tenant = ThreadLocalContextUtil.getTenant();
        List<String> audiences = jwt.getAudience();
        if (tenant == null) {
            // No tenant means TenantAwareHeaderFilter let the request through without
            // resolving one, so there is nothing to compare the audience against and the
            // token cannot be accepted for this request. Without this the line below
            // dereferences null and the caller gets a 500 instead of a 401. The one path
            // that legitimately runs without a tenant, /oauth/token_key, does not reach
            // this validator at all - it is on the chain with no resource server, see
            // ResourceServerConfig - so this is the safety net for anything else.
            // warn, not error: a caller decides how often this happens by sending a
            // bearer token to a path with no tenant, and ERROR should mean something an
            // operator has to act on
            String message = "No tenant in context, cannot verify the token audience";
            logger.warn(message);
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, message, null));
        }
        boolean matches = audiences != null && audiences.stream().anyMatch(a -> tenant.getSchemaName().equals(a));
        if (matches) {
            return OAuth2TokenValidatorResult.success();
        }
        String message = "Token audiences " + audiences + " are not matching with request " + tenant.getSchemaName();
        logger.error(message);
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, message, null));
    }
}
