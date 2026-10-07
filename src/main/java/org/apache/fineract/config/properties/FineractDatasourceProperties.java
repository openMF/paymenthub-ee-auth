package org.apache.fineract.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * The tenant database connection: {@code fineract.datasource.core.*} and {@code fineract.datasource.common.*}.
 *
 * <p>
 * {@code fineract.datasource.core.auto-update} is not here. It is read as
 * {@code @Value("${fineract.datasource.core.auto-update:true}")}: a missing key means {@code true}, but an empty one
 * stops startup. A record cannot do both, because an empty value binds to {@code null} and a default would then turn
 * it into {@code true}. So {@code TenantDatabaseUpgradeService} keeps that {@code @Value}.
 * </p>
 *
 * @param core
 *            the core database server and its credentials
 * @param common
 *            the JDBC protocol, subprotocol and driver
 */
@Validated
@ConfigurationProperties(prefix = "fineract.datasource")
public record FineractDatasourceProperties(@NotNull @Valid Core core, @NotNull @Valid Common common) {

    /**
     * {@code fineract.datasource.core.*}.
     *
     * @param host
     *            database host
     * @param port
     *            database port
     * @param schema
     *            name of the core schema
     * @param username
     *            database user
     * @param password
     *            password of that user
     */
    public record Core(@NotNull String host, @NotNull Integer port, @NotNull String schema, @NotNull String username,
            @NotNull String password) {
    }

    /**
     * {@code fineract.datasource.common.*}.
     *
     * @param protocol
     *            JDBC protocol, {@code jdbc}
     * @param subprotocol
     *            JDBC subprotocol, {@code mysql}
     * @param driverclassName
     *            JDBC driver class, from {@code driverclass_name}
     */
    public record Common(@NotNull String protocol, @NotNull String subprotocol, @NotNull String driverclassName) {
    }
}
