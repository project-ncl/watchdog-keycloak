package org.jboss.pnc.watchdog.keycloak.config;

import java.util.List;

import lombok.Data;

/**
 * Specify roles that a regular user should, and should not have
 */
@Data
public class WatchdogDefault {

    /**
     * List of roles that a user should have. Regex allowed. For client role, they are specified as: '${client}:${role}'
     */
    private List<String> allowedRoles;

    /**
     * List of roles that a user shouldn't have. Regex allowed. For client role, they are specified as:
     * '${client}:${role}'
     */
    private List<String> deniedRoles;
}
