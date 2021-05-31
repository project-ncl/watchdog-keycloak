package org.jboss.pnc.watchdog.keycloak.config;

import static org.assertj.core.api.Assertions.*;

import java.io.File;
import java.io.FileNotFoundException;

import org.assertj.core.util.Lists;
import org.junit.jupiter.api.Test;

class ConfigurationTest {

    @Test
    public void testParseConfiguration() throws FileNotFoundException {

        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("config.yaml").getFile());

        Configuration configuration = Configuration.parseConfiguration(file.getAbsolutePath());

        assertThat(configuration).isNotNull();

        // Verify keycloak
        assertThat(configuration.getKeycloak().getServer()).isEqualTo("https://localhost:8080/auth");
        assertThat(configuration.getKeycloak().getRealm()).isEqualTo("realm-test");
        assertThat(configuration.getKeycloak().getUser()).isEqualTo("read-only-test");
        assertThat(configuration.getKeycloak().getClient()).isEqualTo("account");

        // Verify watchdog
        assertThat(configuration.getWatchdog()).hasSize(2);
        assertThat(configuration.getWatchdog().get(1).getName()).isEqualTo("muggles");
        assertThat(configuration.getWatchdog().get(1).getUsers()).isEqualTo(Lists.list("josie"));
        assertThat(configuration.getWatchdog().get(1).getAllowedRoles()).isEqualTo(Lists.list("user"));
        assertThat(configuration.getWatchdog().get(1).getDeniedRoles()).isEqualTo(Lists.list("*"));

        // Verify defaultRoles
        assertThat(configuration.getDefaultRoles()).isEqualTo(Lists.list("user", "goodboy"));

    }

}
