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

    @Value("${fineract.datasource.core.host}")
    private String hostname;

    @Value("${fineract.datasource.core.port}")
    private int port;

    @Value("${fineract.datasource.core.username}")
    private String username;

    @Value("${fineract.datasource.core.password}")
    private String password;

    @Value("${fineract.datasource.common.protocol}")
    private String jdbcProtocol;

    @Value("${fineract.datasource.common.subprotocol}")
    private String jdbcSubprotocol;

    @Value("${fineract.datasource.common.driverclass_name}")
    private String driverClass;

    @Value("${token.access.validity-seconds}")
    private String tokenAccessValiditySeconds;

    @Value("${token.refresh.validity-seconds}")
    private String tokenRefreshValiditySeconds;

    @Value("#{'${tenants}'.split(',')}")
    private List<String> tenants;

    /**
     * Whether this service owns the core schema. The tenant schemas already have this
     * switch, one per tenant, in the auto_update column read by flywayTenants() below;
     * the core schema had none, and it is the one that cannot recover.
     */
    @Value("${fineract.datasource.core.auto-update:true}")
    private boolean coreAutoUpdateEnabled;

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
        if (coreAutoUpdateEnabled) {
            flywayDefaultSchema();
            insertTenants();
        } else {
            logger.info("Core schema auto-update is off: not migrating the core schema and not registering tenants."
                    + " Tenants are read from tenant_server_connections as another service wrote them.");
        }
        flywayTenants();
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