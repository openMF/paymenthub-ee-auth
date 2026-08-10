package org.apache.fineract.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.concurrent.TimeUnit;

/**
 * Ehcache 2 (net.sf.ehcache) is gone: Spring 6 removed EhCacheCacheManager.
 * Caffeine replaces it with the same behavior for the single cache used here:
 * max 1000 entries, entries expire 10 seconds after write. The old
 * CacheEventLogger/CustomCacheEventListenerFactory (Ehcache-specific SPI) are
 * replaced by Caffeine's removal listener, which logs the same kind of events.
 * Same swap already done in ph-ee-identity-account-mapper and ph-ee-operations-app.
 */
@EnableCaching
@Configuration
@ConditionalOnExpression("${caching.enabled}")
public class CacheConfig {

    public static final String CACHE_USER_BY_NAME = "userByName";

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Bean
    @Primary
    public CacheManager cacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager(CACHE_USER_BY_NAME);
        cacheManager.setCaffeine(Caffeine.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(10, TimeUnit.SECONDS)
                .removalListener((key, value, cause) -> logger.info("Cache remove {} {} ({})", key, value, cause)));
        return cacheManager;
    }
}
