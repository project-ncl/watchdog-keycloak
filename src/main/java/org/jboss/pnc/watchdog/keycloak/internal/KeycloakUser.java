package org.jboss.pnc.watchdog.keycloak.internal;

import java.util.List;

import lombok.Data;

/**
 * Internal representation of a keycloak user
 */
@Data
public class KeycloakUser {

    private String username;
    private List<String> roles;
}
