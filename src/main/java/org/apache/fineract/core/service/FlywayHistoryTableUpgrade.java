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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Moves a Flyway 2.x history table to the layout Flyway 10 expects.
 *
 * The old app ran Flyway 2.x, which kept its history in a table called
 * "schema_version". Flyway 10 uses "flyway_schema_history" and a different
 * layout: "installed_rank" is the primary key, the old "version_rank" column is
 * gone, "description" is NOT NULL and "version" is nullable. Flyway 10 can read
 * the old table but cannot insert into it, so the first pending migration on an
 * existing database fails. Flyway used to do this conversion by itself (up to
 * Flyway 4), that code was removed, so we do it here before calling migrate().
 *
 * The old table is COPIED, never renamed or dropped: "schema_version" is left
 * exactly as it was. That matters for two reasons beyond keeping a backup.
 *
 * First, this application is not always the only thing using the schema. On the
 * gazelle cluster ph-ee-operations-app owns the history of the core "tenants"
 * schema and of every tenant schema, and it is still running a Flyway 2 build, so
 * "schema_version" is its live table, not an leftover. Renaming it would take that
 * history away from a service that is up and serving traffic, and it would only
 * find out at its next restart - with no history, Flyway 2 baselines and treats
 * every migration as pending against a schema that already has the objects.
 *
 * Second, it makes the conversion reversible. Rolling an image back to a Flyway 2
 * build finds its history where it left it.
 *
 * Does nothing on a fresh database, and nothing if it has already run: the check
 * for "flyway_schema_history" comes first, so a second start is a no-op. Nothing
 * here removes "schema_version", so there is no window in which neither table
 * exists and no interrupted state to recover from.
 *
 * Copying is not enough to make this app safe on a schema it does not own - the
 * migration numbers still collide, see the comment in
 * TenantDatabaseUpgradeService - but it does mean the collision damages only this
 * app and not the one that owns the schema.
 *
 * How a failure here surfaces depends on which schema it happens in, and the two
 * are not the same. TenantDatabaseUpgradeService.flywayDefaultSchema() lets the
 * exception escape, so a problem in the core schema stops startup. Its
 * flywayTenants() loop catches Exception per tenant and only logs it, so on a
 * tenant schema a failure degrades to one ERROR line: the context starts, the
 * readiness probe goes green and that tenant serves traffic against a schema whose
 * migration state is unknown. The catch predates this class and widening it is a
 * startup-behaviour decision for a multi-tenant deployment, not something to change
 * inside a migration - but anyone reading this should know it can be swallowed.
 */
final class FlywayHistoryTableUpgrade {

    private static final Logger logger = LoggerFactory.getLogger(FlywayHistoryTableUpgrade.class);

    private static final String LEGACY_TABLE = "schema_version";
    private static final String CURRENT_TABLE = "flyway_schema_history";

    private FlywayHistoryTableUpgrade() {
    }

    /**
     * @return true if this call moved a history table written by an older Flyway,
     *         which is the only situation where the caller needs Flyway.repair():
     *         those rows carry checksums the current version will not validate.
     *         False when there was nothing to do, so repair() can be skipped and
     *         does not get a chance to mark rows DELETED on every restart.
     */
    static boolean upgradeIfNeeded(DataSource dataSource) {
        try (Connection connection = dataSource.getConnection()) {
            String schema = connection.getCatalog();
            if (tableExists(connection, schema, CURRENT_TABLE)) {
                return false; // already on the Flyway 10 layout
            }
            if (!tableExists(connection, schema, LEGACY_TABLE)) {
                return false; // fresh database, Flyway will create its own table
            }
            if (columnExists(connection, schema, LEGACY_TABLE, "version_rank")) {
                logger.info("Found a Flyway 2.x history table in schema {}, copying it to {}", schema, CURRENT_TABLE);
                convertLegacyTable(connection);
            } else {
                // "schema_version" written by a recent Flyway (a run of this app
                // that still passed .table("schema_version")): layout is already
                // right, only the name is old. Untested path - this app has never
                // written that table - so it copies like the branch above rather
                // than doing anything clever.
                logger.info("Copying {} to {} in schema {}", LEGACY_TABLE, CURRENT_TABLE, schema);
                try (Statement statement = connection.createStatement()) {
                    statement.execute("CREATE TABLE " + CURRENT_TABLE + " LIKE " + LEGACY_TABLE);
                    statement.execute("INSERT INTO " + CURRENT_TABLE + " SELECT * FROM " + LEGACY_TABLE);
                }
                commitIfNeeded(connection);
            }
            return true;
        } catch (SQLException e) {
            // If two instances start at the same moment on the same schema, one wins the
            // CREATE TABLE and the other lands here. On a tenant schema flywayTenants()
            // catches it; on the core schema nothing does, so that instance fails to start
            // and the next attempt finds the table already there and returns false. It
            // recovers by itself, but the log line to look for is this one, not a
            // corrupted history.
            throw new IllegalStateException("Cannot upgrade the Flyway history table", e);
        }
    }

    private static void convertLegacyTable(Connection connection) throws SQLException {
        // the cleanup below must only remove a table this call created. If two
        // instances start together they both get here, the CREATE TABLE of the loser
        // fails, and dropping on the way out would delete the table the winner has
        // just filled.
        boolean tableCreated = false;
        try (Statement statement = connection.createStatement()) {
            try {
                // same DDL Flyway 10 itself uses for MySQL
                statement.execute("CREATE TABLE " + CURRENT_TABLE + " ("
                        + "installed_rank INT NOT NULL,"
                        + "version VARCHAR(50),"
                        + "description VARCHAR(200) NOT NULL,"
                        + "type VARCHAR(20) NOT NULL,"
                        + "script VARCHAR(1000) NOT NULL,"
                        + "checksum INT,"
                        + "installed_by VARCHAR(100) NOT NULL,"
                        + "installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                        + "execution_time INT NOT NULL,"
                        + "success BOOL NOT NULL,"
                        + "CONSTRAINT " + CURRENT_TABLE + "_pk PRIMARY KEY (installed_rank)"
                        + ") ENGINE=InnoDB");
                tableCreated = true;
                statement.execute("CREATE INDEX " + CURRENT_TABLE + "_s_idx ON " + CURRENT_TABLE + " (success)");
                // description was nullable before and is NOT NULL now; "INIT" was
                // renamed to "BASELINE" when Flyway 5 came out
                statement.execute("INSERT INTO " + CURRENT_TABLE
                        + " (installed_rank, version, description, type, script, checksum,"
                        + " installed_by, installed_on, execution_time, success)"
                        + " SELECT installed_rank, version, COALESCE(description, ''),"
                        + " CASE WHEN type = 'INIT' THEN 'BASELINE' ELSE type END,"
                        + " script, checksum, installed_by, installed_on, execution_time, success"
                        + " FROM " + LEGACY_TABLE);
                commitIfNeeded(connection);
            } catch (SQLException e) {
                // leave no half-built table behind: the next start must be able to retry
                if (tableCreated) {
                    try {
                        if (!connection.getAutoCommit()) {
                            connection.rollback();
                        }
                        statement.execute("DROP TABLE IF EXISTS " + CURRENT_TABLE);
                        commitIfNeeded(connection);
                    } catch (SQLException cleanupFailure) {
                        e.addSuppressed(cleanupFailure);
                    }
                }
                throw e;
            }
        }
    }

    /**
     * The tenant datasources are built with autoCommit off (see
     * DataSourcePerTenantService), so the row copy has to be committed by hand.
     * MySQL commits on its own after each DDL statement, but not after the
     * INSERT, and the pool rolls back whatever is left open.
     */
    private static void commitIfNeeded(Connection connection) throws SQLException {
        if (!connection.getAutoCommit()) {
            connection.commit();
        }
    }

    // information_schema rather than DatabaseMetaData: getTables/getColumns take
    // LIKE patterns, and every name here contains an underscore, which is a
    // single-character wildcard in a pattern.
    private static boolean tableExists(Connection connection, String schema, String table) throws SQLException {
        return exists(connection, "SELECT 1 FROM information_schema.tables"
                + " WHERE table_schema = ? AND table_name = ?", schema, table);
    }

    private static boolean columnExists(Connection connection, String schema, String table, String column) throws SQLException {
        return exists(connection, "SELECT 1 FROM information_schema.columns"
                + " WHERE table_schema = ? AND table_name = ? AND column_name = ?", schema, table, column);
    }

    private static boolean exists(Connection connection, String sql, String... parameters) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                statement.setString(i + 1, parameters[i]);
            }
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next();
            }
        }
    }
}
