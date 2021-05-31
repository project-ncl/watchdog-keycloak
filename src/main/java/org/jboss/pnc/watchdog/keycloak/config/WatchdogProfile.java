package org.jboss.pnc.watchdog.keycloak.config;

import java.util.List;

import lombok.Data;

/**
 * Specify a list of users and which roles that user should, and should not have
 */
@Data
public class WatchdogProfile {

    /**
     * Name of profile
     */
    private String name;

    /**
     * List of users that should obey the constraints
     */
    private List<String> users;

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
