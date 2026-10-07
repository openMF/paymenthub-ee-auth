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
package org.apache.fineract;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.fineract.core.service.TenantAwareHeaderFilter;
import org.apache.fineract.organisation.tenant.TenantServerConnectionRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class,
        DataSourceTransactionManagerAutoConfiguration.class,
        FlywayAutoConfiguration.class})
@ConfigurationPropertiesScan("org.apache.fineract.config.properties")
public class ServerApplication {

    /**
     * Spring security filter chain ordering, the tenant header filter
     * must run before this to set current tenant so it's order has to be lower to gain priority
     */
    @Value("${spring.security.filter.order}")
    private int securityFilterOrder;

    @Bean
    public ObjectMapper mapper() {
        return new ObjectMapper();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider customAuthenticationProvider(PasswordEncoder passwordEncoder,
                                                                  UserDetailsService userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public FilterRegistrationBean tenantFilter(TenantServerConnectionRepository repository) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(new TenantAwareHeaderFilter(repository));
        registration.addUrlPatterns("/*");
        registration.setName("tenantFilter");
        registration.setOrder(securityFilterOrder - 4);
        return registration;
    }

    @Bean
    public FilterRegistrationBean corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        // addAllowedOriginPattern, not addAllowedOrigin: since Spring 5.3 the literal "*"
        // together with allowCredentials(true) is rejected at request time
        // ("When allowCredentials is true, allowedOrigins cannot contain the special
        // value \"*\""), which would turn every cross-origin call from the web console
        // into a 500. The pattern form allows the same set of origins and echoes the
        // caller's Origin back, which is what a credentialed request needs.
        config.addAllowedOriginPattern("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
        bean.setOrder(securityFilterOrder - 5);
        return bean;
    }

    @Bean
    public AuthenticationManager authenticationManager(DaoAuthenticationProvider customAuthenticationProvider) {
        List<AuthenticationProvider> providers = new ArrayList<>();
        providers.add(customAuthenticationProvider);
        return new ProviderManager(providers);
    }

    public static void main(String[] args) throws Exception {
        SpringApplication.run(ServerApplication.class, args);
    }
}