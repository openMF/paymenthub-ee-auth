package org.apache.fineract.config.properties;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

/**
 * Every property these records ask for has to be there, or the service must refuse to start and say which one is
 * missing. That is what the plain {@code @Value} declarations did before they were replaced, so these tests hold the
 * replacement to the same promise, and they read the real application.properties rather than a copy of it.
 */
class ShippedConfigBindsTest {

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties({ FineractDatasourceProperties.class, TokenProperties.class })
    static class AllRecords {}

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(FineractDatasourceProperties.class)
    static class OnlyDatasource {}

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(TokenProperties.class)
    static class OnlyToken {}

    /** One configuration class per record, keyed by the prefix that record binds. */
    private static final Map<String, Class<?>> ONE_RECORD_EACH = Map.of("fineract.datasource", OnlyDatasource.class, "token",
            OnlyToken.class);

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner().withConfiguration(
                AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class, ValidationAutoConfiguration.class));
    }

    private ApplicationContextRunner withShippedProperties() {
        return runner().withInitializer(new ConfigDataApplicationContextInitializer());
    }

    @Test
    void theShippedApplicationPropertiesFillEveryField() {
        withShippedProperties().withUserConfiguration(AllRecords.class).run(context -> {
            assertThat(context).hasNotFailed();
            FineractDatasourceProperties datasource = context.getBean(FineractDatasourceProperties.class);
            assertThat(datasource.core().host()).isEqualTo("operations-mysql");
            assertThat(datasource.core().port()).isEqualTo(3306);
            assertThat(datasource.core().schema()).isEqualTo("tenants");
            assertThat(datasource.core().username()).isEqualTo("root");
            assertThat(datasource.core().password()).isNotEmpty();
            assertThat(datasource.common().protocol()).isEqualTo("jdbc");
            assertThat(datasource.common().subprotocol()).isEqualTo("mysql");
            // application.properties spells this key driverclass_name
            assertThat(datasource.common().driverclassName()).isEqualTo("com.mysql.cj.jdbc.Driver");
            TokenProperties token = context.getBean(TokenProperties.class);
            // kept as text, because they are passed on as text to the tenant schema migrations
            assertThat(token.access().validitySeconds()).isEqualTo("600");
            assertThat(token.refresh().validitySeconds()).isEqualTo("43200");
        });
    }

    @Test
    void everyRecordRefusesToStartWhenItsSectionIsMissing() {
        ONE_RECORD_EACH.forEach((prefix, configuration) -> runner().withUserConfiguration(configuration).run(context -> {
            assertThat(context).as("context with nothing configured under '%s'", prefix).hasFailed();
            assertThat(context.getStartupFailure()).as("failure for '%s'", prefix).hasStackTraceContaining("BindValidationException")
                    .hasStackTraceContaining("Binding validation errors on " + prefix);
        }));
    }

    @Test
    void aMissingKeyInsideAGroupStopsStartup() {
        // only fineract.datasource.core.password is missing, so this checks that @Valid reaches the nested record
        runner().withUserConfiguration(OnlyDatasource.class)
                .withPropertyValues("fineract.datasource.core.host=h", "fineract.datasource.core.port=3306",
                        "fineract.datasource.core.schema=s", "fineract.datasource.core.username=u",
                        "fineract.datasource.common.protocol=jdbc", "fineract.datasource.common.subprotocol=mysql",
                        "fineract.datasource.common.driverclass_name=d")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("Binding validation errors on fineract.datasource")
                            .hasStackTraceContaining("core.password");
                });
    }

    @Test
    void aValueSetToNothingOnANumberFieldStopsStartup() {
        withShippedProperties().withUserConfiguration(OnlyDatasource.class).withPropertyValues("fineract.datasource.core.port=")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("Binding validation errors on fineract.datasource");
                });
    }

    @Test
    void aValueSetToNothingOnAStringFieldIsAcceptedJustAsItWasBefore() {
        withShippedProperties().withUserConfiguration(OnlyToken.class).withPropertyValues("token.access.validity-seconds=")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(TokenProperties.class).access().validitySeconds()).isEmpty();
                });
    }
}
