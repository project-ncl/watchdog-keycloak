package org.jboss.pnc.watchdog.keycloak.config;

import lombok.Data;

/**
 * DTO representing the Keycloak information to connect to it. The user here is the user who has
 * realm-management:view-users permissions to be able to view all the users and their roles
 */
@Data
public class KeycloakConfig {

    /**
     * Server name. Should be full url, like https://localhost:8080/auth
     */
    private String server;

    /**
     * realm to check
     */
    private String realm;

    /**
     * User to authenticate to keycloak as to get all the information
     */
    private String user;

    /**
     * Client information. Set to 'account' by default
     */
    private String client = "account";
}
