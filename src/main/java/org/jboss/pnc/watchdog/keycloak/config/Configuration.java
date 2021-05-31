package org.jboss.pnc.watchdog.keycloak.config;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.List;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import lombok.Data;

/**
 * Main configuration of the watchdog-keycloak. You can define how to connect to keycloak, the roles that users should
 * have, and the default roles set by default to all users
 */
@Data
public class Configuration {

    /**
     * Define how to talk to the keycloak server here
     */
    private KeycloakConfig keycloak;

    /**
     * Define the constraints of users. Some users should have some roles, and should not have other roles. You can
     * define the list of constraints here. The roles can be defined using regex
     */
    private List<WatchdogProfile> watchdog;

    /**
     * Define the constraints for the regular users
     */
    private WatchdogDefault watchdogDefault;

    /**
     * Define the list of default roles that all users should have
     */
    private List<String> defaultRoles;

    public static Configuration parseConfiguration(String path) throws FileNotFoundException {
        Yaml yaml = new Yaml(new Constructor(Configuration.class));
        return yaml.load(new FileReader(path));
    }
}
