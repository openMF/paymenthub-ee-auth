package org.apache.fineract.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Token validity: {@code token.access.*} and {@code token.refresh.*}.
 *
 * <p>
 * The values stay strings, as they were in the {@code @Value} fields this replaces: they are passed on as text to the
 * tenant schema migrations.
 * </p>
 *
 * @param access
 *            access token settings
 * @param refresh
 *            refresh token settings
 */
@Validated
@ConfigurationProperties(prefix = "token")
public record TokenProperties(@NotNull @Valid Access access, @NotNull @Valid Refresh refresh) {

    /**
     * {@code token.access.*}.
     *
     * @param validitySeconds
     *            access token validity, in seconds
     */
    public record Access(@NotNull String validitySeconds) {
    }

    /**
     * {@code token.refresh.*}.
     *
     * @param validitySeconds
     *            refresh token validity, in seconds
     */
    public record Refresh(@NotNull String validitySeconds) {
    }
}
