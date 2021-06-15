package org.jboss.pnc.watchdog.keycloak;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.jboss.pnc.watchdog.keycloak.config.Configuration;
import org.jboss.pnc.watchdog.keycloak.config.WatchdogDefault;
import org.jboss.pnc.watchdog.keycloak.config.WatchdogProfile;
import org.jboss.pnc.watchdog.keycloak.internal.KeycloakServer;
import org.jboss.pnc.watchdog.keycloak.internal.KeycloakUser;

import com.google.common.collect.Sets;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Utils {

    /**
     * check if user / client service account role matches the constraints defined in the config file If everything is
     * fine, return true, else false
     *
     * @param configuration
     * @param keycloakServer
     * @return
     */
    public static boolean checkUserRoles(Configuration configuration, KeycloakServer keycloakServer) {
        log.info("Verifying user roles...");

        Set<KeycloakUser> users = keycloakServer.getUsers();
        Set<KeycloakUser> serviceAccounts = keycloakServer.getServiceAccountClients();
        Map<String, KeycloakUser> userMap = users.stream()
                .collect(Collectors.toMap(KeycloakUser::getUsername, self -> self));

        serviceAccounts.forEach(serviceAccount -> userMap.put(serviceAccount.getUsername(), serviceAccount));

        // Make a copy of the users list that are un-processed
        Set<String> usersUnprocessed = new HashSet<>(userMap.keySet());

        List<WatchdogProfile> profiles = configuration.getWatchdog();

        boolean allGood = true;

        for (WatchdogProfile profile : profiles) {

            log.info("Processing profile: {}...", profile.getName());
            for (String user : profile.getUsers()) {

                if (userMap.containsKey(user)) {
                    usersUnprocessed.remove(user);

                    KeycloakUser keycloakUser = userMap.get(user);
                    log.info("Verifying user: {}", user);

                    boolean isValid = compareRoles(
                            keycloakUser.getRoles(),
                            profile.getAllowedRoles(),
                            profile.getDeniedRoles(),
                            keycloakUser.isServiceAccount());
                    if (!isValid) {
                        allGood = false;
                    }
                } else {
                    log.error("Couldn't find user: {}", user);
                    allGood = false;
                }
            }
        }

        // Verifying regular users
        log.info("Checking the rest of the users...");
        WatchdogDefault watchdogDefault = configuration.getWatchdogDefault();
        for (String user : usersUnprocessed) {
            KeycloakUser keycloakUser = userMap.get(user);
            log.info("Verifying user: {}", user);

            boolean isValid = compareRoles(
                    keycloakUser.getRoles(),
                    watchdogDefault.getAllowedRoles(),
                    watchdogDefault.getDeniedRoles(),
                    keycloakUser.isServiceAccount());
            if (!isValid) {
                allGood = false;
            }
        }

        return allGood;
    }

    /**
     * If a user is not a service account and missing allowed roles, consider it a warning but not a fail. If a user is
     * a service account and missing allowed roles, consider it a fail If a user has denied roles in its current roles,
     * consider it a fail
     *
     * @param currentRoles
     * @param allowedRoles
     * @param deniedRoles
     * @param isServiceAccount
     * @return false if validation fails, true otherwise
     */
    @NonNull
    static boolean compareRoles(
            List<String> currentRoles,
            List<String> allowedRoles,
            List<String> deniedRoles,
            boolean isServiceAccount) {

        List<String> allowedRolesMissing = new ArrayList<>();
        List<String> deniedRolesPresent = new ArrayList<>();

        // Check if there are allowed roles missing from a user
        for (String allowedRole : allowedRoles) {

            boolean found = false;

            for (String currentRole : currentRoles) {

                Pattern pattern = Pattern.compile(allowedRole);
                Matcher matcher = pattern.matcher(currentRole);

                if (matcher.find()) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                allowedRolesMissing.add(allowedRole);
            }
        }

        // Check if the current roles are in the deny roles
        for (String deniedRole : deniedRoles) {

            Pattern pattern = Pattern.compile(deniedRole);
            boolean found = false;
            for (String currentRole : currentRoles) {
                Matcher matcher = pattern.matcher(currentRole);
                if (matcher.find()) {
                    found = true;
                    break;
                }
            }

            if (found) {
                deniedRolesPresent.add(deniedRole);
            }
        }

        if (!allowedRolesMissing.isEmpty()) {
            if (isServiceAccount) {
                log.error("User missing roles: {}", allowedRolesMissing);
            } else {
                log.warn("User missing roles: {}", allowedRolesMissing);
            }
        }

        if (!deniedRolesPresent.isEmpty()) {
            log.error("User has roles which are in the deny list: {}", deniedRolesPresent);
        }

        if ((!allowedRolesMissing.isEmpty() && isServiceAccount) || !deniedRolesPresent.isEmpty()) {
            return false;
        } else {
            return true;
        }
    }

    public static boolean checkDefaultRoles(Configuration configuration, KeycloakServer keycloakServer) {

        log.info("Verifying default roles");

        Set<String> defaultRoles = keycloakServer.getDefaultRoles();
        Set<String> shouldBeDefaultRoles = new HashSet<>(configuration.getDefaultRoles());

        boolean defaultRolesMatch = defaultRoles.equals(shouldBeDefaultRoles);

        if (!defaultRolesMatch) {

            Sets.SetView<String> definedInKeycloakButNotInConfig = Sets.difference(defaultRoles, shouldBeDefaultRoles);
            if (!definedInKeycloakButNotInConfig.isEmpty()) {
                log.error("There are default roles in Keycloak not defined in the config file:");
                definedInKeycloakButNotInConfig.forEach(role -> log.error("- " + role));
            }

            Sets.SetView<String> definedInConfigButNotInKeycloak = Sets.difference(shouldBeDefaultRoles, defaultRoles);
            if (!definedInConfigButNotInKeycloak.isEmpty()) {
                log.error("There are default roles missing in Keycloak:");
                definedInConfigButNotInKeycloak.forEach(role -> log.error("- " + role));
            }
        }
        return defaultRolesMatch;
    }
}
