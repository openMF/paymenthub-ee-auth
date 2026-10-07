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

import org.flywaydb.core.Flyway;
import org.apache.fineract.organisation.tenant.TenantServerConnection;
import org.apache.fineract.organisation.tenant.TenantServerConnectionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.fineract.config.properties.FineractDatasourceProperties;
import org.apache.fineract.config.properties.TokenProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.fineract.config.ResourceServerConfig.IDENTITY_PROVIDER_RESOURCE_ID;

@Service
public class TenantDatabaseUpgradeService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private TenantServerConnectionRepository repository;

    @Autowired
    private DataSourcePerTenantService dataSourcePerTenantService;

    private final String hostname;

    private final int port;

    private final String username;

    private final String password;

    private final String jdbcProtocol;

    private final String jdbcSubprotocol;

    private final String driverClass;

    private final String tokenAccessValiditySeconds;

    private final String tokenRefreshValiditySeconds;

    @Value("#{'${tenants}'.split(',')}")
    private List<String> tenants;

    /**
     * Whether this service builds its own database. Off, it applies no migration to any
     * schema - core or tenant - and only reads what another service put there.
     *
     * It has to cover the tenant schemas too, not only the core one. The tenant schemas
     * do have their own switch, the auto_update column, but that column lives in
     * tenant_server_connections, which is a table in the core schema this service does
     * not own: telling an operator to set auto_update = 0 means asking them to write into
     * the very schema we are trying not to touch. And it defaults to 1 on a real
     * deployment - it is 1 for both tenants on gazelle - so leaving the tenant half
     * ungated means the switch does not do what its name promises.
     */
    @Value("${fineract.datasource.core.auto-update:true}")
    private boolean autoUpdateEnabled;

    public TenantDatabaseUpgradeService(FineractDatasourceProperties datasource, TokenProperties token) {
        this.hostname = datasource.core().host();
        this.port = datasource.core().port();
        this.username = datasource.core().username();
        this.password = datasource.core().password();
        this.jdbcProtocol = datasource.common().protocol();
        this.jdbcSubprotocol = datasource.common().subprotocol();
        this.driverClass = datasource.common().driverclassName();
        this.tokenAccessValiditySeconds = token.access().validitySeconds();
        this.tokenRefreshValiditySeconds = token.refresh().validitySeconds();
    }

    @PostConstruct
    public void setupEnvironment() {
        // Both calls below write to the core schema: one applies this repository's
        // migrations, the other registers tenants in tenant_server_connections. On a
        // deployment where the core schema belongs to another service the first one is
        // fatal - ph-ee-operations-app ships the same table as V2 and this repository
        // ships it as V1, so Flyway replays it out of order, the CREATE TABLE fails on a
        // table that is already there, and flywayDefaultSchema() lets the exception
        // escape, so the application does not start at all. (The same collision on a
        // tenant schema is caught per tenant and only logged.)
        //
        // Turning this off makes the service a reader of a schema it does not own:
        // whoever owns it applies the migrations and registers the tenants. Everything
        // this service needs is already there in that case - m_appuser, m_role,
        // m_permission and oauth_client_details all come from the owner.
        //
        // Default true, so a standalone deployment with a database of its own keeps
        // building it exactly as before.
        //
        // flywayTenants() is gated as well, and that half is not theoretical. Run against
        // the real gazelle database with only the core call skipped, Flyway finds a tenant
        // schema of 255 tables with no history of its own, BASELINES it - creating a
        // flyway_schema_history in a schema owned by ph-ee-operations-app - then tries to
        // apply V2 on top of tables that already exist and fails. What is left behind is a
        // history table with a failed row in it, which blocks Flyway for whoever does own
        // that schema until someone runs repair() by hand. The loop catches per tenant and
        // only logs, so the service starts and the pod goes green with one ERROR line.
        if (autoUpdateEnabled) {
            flywayDefaultSchema();
            insertTenants();
            flywayTenants();
        } else {
            logger.info("Database auto-update is off: applying no migration to the core schema or to any tenant,"
                    + " and not registering tenants. Every schema is read as another service wrote it.");
        }
    }

    private void flywayTenants() {
        for (TenantServerConnection tenant : repository.findAll()) {
            if (tenant.isAutoUpdateEnabled()) {
                try {
                    ThreadLocalContextUtil.setTenant(tenant);
                    Map<String, String> placeholders = new HashMap<>();
                    placeholders.put("tenantDatabase", tenant.getSchemaName()); // add tenant as aud claim
                    placeholders.put("accessTokenValidity", tokenAccessValiditySeconds);
                    placeholders.put("refreshTokenValidity", tokenRefreshValiditySeconds);
                    placeholders.put("identityProviderResourceId", IDENTITY_PROVIDER_RESOURCE_ID); // add identity provider as aud claim
                    // Flyway moved from setters to a fluent configure() API.
                    // The Flyway 2.x history table (schema_version) is converted to the Flyway 10
                    // one (flyway_schema_history) first: Flyway 10 can read the old table but
                    // cannot write to it.
                    DataSource tenantDataSource = dataSourcePerTenantService.retrieveDataSource();
                    boolean historyConverted = FlywayHistoryTableUpgrade.upgradeIfNeeded(tenantDataSource);
                    final Flyway fw = Flyway.configure()
                            .dataSource(tenantDataSource)
                            .locations("sql/migrations/tenant")
                            // Not in the old config. Flyway 10 refuses a non-empty schema that has no
                            // history table of its own, which is what this service finds on a tenant
                            // database created by something else, so the flag is needed to start at all.
                            //
                            // It does NOT make this service and ph-ee-operations-app safe to point at
                            // the same tenant schema, and nothing here can: the two ship 27 colliding
                            // version numbers with different scripts, offset by one (V27 is
                            // oauth_changes here and add_refund_permission there). Flyway keys a
                            // migration by version, so whichever runs second sees history rows whose
                            // script and checksum do not match its own files. Worse, flywayTenants()
                            // below catches per tenant and only logs, so that tenant would come up with
                            // an unknown migration state instead of failing loudly.
                            //
                            // This predates the migration - the same overlap existed under Flyway 2 -
                            // and it does not bite today because this service is not deployed. It has
                            // to be settled before it is: one owner for the tenant migrations, or
                            // separate schemas.
                            .baselineOnMigrate(true)
                            .outOfOrder(true)
                            .placeholders(placeholders)
                            .load();
                    // only after a conversion: the history written by Flyway 2.x holds checksums
                    // computed with the old algorithm and Flyway 10 would fail validation on them,
                    // which repair() re-computes. That is a one-time condition, so the call is
                    // gated: repair() also marks as DELETED any history row whose script is no
                    // longer on disk, and running it on every restart would keep rewriting the
                    // history of a schema carrying migrations this repo does not ship.
                    if (historyConverted) {
                        fw.repair();
                    }
                    fw.migrate();
                } catch (Exception e) {
                    logger.error("Error when running flyway on tenant: {}", tenant.getSchemaName(), e);
                } finally {
                    ThreadLocalContextUtil.clear();
                }
            }
        }
    }

    private void insertTenants() {
        for(String tenant : tenants) {
            TenantServerConnection existingTenant = repository.findOneBySchemaName(tenant);
            if(existingTenant == null) {
                TenantServerConnection tenantServerConnection = new TenantServerConnection();
                tenantServerConnection.setSchemaName(tenant);
                tenantServerConnection.setSchemaServer(hostname);
                tenantServerConnection.setSchemaServerPort(String.valueOf(port));
                tenantServerConnection.setSchemaUsername(username);
                tenantServerConnection.setSchemaPassword(password);
                tenantServerConnection.setAutoUpdateEnabled(true);
                repository.saveAndFlush(tenantServerConnection);
            }
        }
    }

    private void flywayDefaultSchema() {
        DataSource coreDataSource = dataSourcePerTenantService.retrieveDataSource();
        // convert the Flyway 2.x history table if this database has one (see flywayTenants)
        boolean historyConverted = FlywayHistoryTableUpgrade.upgradeIfNeeded(coreDataSource);
        final Flyway fw = Flyway.configure()
                .dataSource(coreDataSource)
                .locations("sql/migrations/core")
                .baselineOnMigrate(true)
                .outOfOrder(true)
                .load();
        // gated for the same reason as in flywayTenants
        if (historyConverted) {
            fw.repair();
        }
        fw.migrate();
    }
}