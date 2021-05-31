package org.jboss.pnc.watchdog.keycloak;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.concurrent.Callable;

import org.jboss.pnc.watchdog.keycloak.config.Configuration;
import org.jboss.pnc.watchdog.keycloak.config.KeycloakConfig;
import org.jboss.pnc.watchdog.keycloak.internal.KeycloakServer;

import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;

@Slf4j
@CommandLine.Command(
        name = "check",
        mixinStandardHelpOptions = true,
        version = "awesome",
        description = "Check if our Keycloak server is configured properly")
public class Main implements Callable<Integer> {

    @CommandLine.Option(
            names = { "--config" },
            required = true,
            description = "YAML config file for keycloak and user list")
    private String configFile;

    @CommandLine.Option(
            names = { "--password" },
            required = true,
            description = "Password to authenticate to Keycloak server")
    private String password;

    @Override
    public Integer call() throws Exception {

        File file = new File(configFile);
        if (!file.exists()) {
            log.error("File '{}' doesn't exist!", configFile);
        }
        Configuration configuration = Configuration.parseConfiguration(file.getAbsolutePath());
        KeycloakConfig keycloakCfg = configuration.getKeycloak();
        KeycloakServer keycloakServer = new KeycloakServer(
                keycloakCfg.getServer(),
                keycloakCfg.getRealm(),
                keycloakCfg.getClient(),
                keycloakCfg.getUser(),
                password);

        boolean successUser = Utils.checkUserRoles(configuration, keycloakServer);
        // TODO: doesn't really work yet
        // boolean successDefault = Utils.checkDefaultRoles(configuration, keycloakServer);

        if (successUser) {
            return 0;
        } else {
            return 1;
        }
    }

    public static void main(String[] args) throws FileNotFoundException {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }
}
