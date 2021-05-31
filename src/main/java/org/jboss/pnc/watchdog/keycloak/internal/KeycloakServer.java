package org.jboss.pnc.watchdog.keycloak.internal;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import lombok.NonNull;

/**
 * Class that deals with communication with the Keyclaok server to get all the required information
 */
public class KeycloakServer {

    private Keycloak keycloak;
    private String realm;

    /**
     * Create a new representation of the Keycloak Server
     *
     * @param server Server url: has to be the full url. e.g: https://localhost:8080/auth
     * @param realm Realm where the users belong
     * @param clientId client id used to authenticate with Keycloak
     * @param username username to check for Keycloak users
     * @param password password for the username
     */
    @NonNull
    public KeycloakServer(String server, String realm, String clientId, String username, String password) {

        this.realm = realm;
        keycloak = KeycloakBuilder.builder()
                .serverUrl(server)
                .grantType(OAuth2Constants.PASSWORD)
                .realm(realm)
                .clientId(clientId)
                .username(username)
                .password(password)
                .resteasyClient(new ResteasyClientBuilder().connectionPoolSize(10).build())
                .build();
    }

    /**
     * Get the list of users in Keycloak
     *
     * @return Return the list of users in the realm of the Keycloak server, together with the realm / client roles
     */
    public Set<KeycloakUser> getUsers() {

        Set<KeycloakUser> toReturn = new HashSet<>();

        // get list of users
        List<UserRepresentation> users = keycloak.realm(this.realm).users().list();

        for (UserRepresentation user : users) {

            KeycloakUser keycloakUser = new KeycloakUser();
            toReturn.add(keycloakUser);

            List<String> allRoles = new ArrayList<>();
            keycloakUser.setRoles(allRoles);

            // get more detailed information about the user from Keycloak. UserRepresentation doesn't have the role
            // information
            UserResource resource = keycloak.realm(this.realm).users().get(user.getId());
            keycloakUser.setUsername(user.getUsername());

            // get all the realm roles for the user
            List<RoleRepresentation> realmRoles = resource.roles().getAll().getRealmMappings();

            for (RoleRepresentation role : realmRoles) {
                allRoles.add(role.getName());
            }

            // get all the client roles for the user
            Map<String, ClientMappingsRepresentation> mapping = resource.roles().getAll().getClientMappings();
            for (Map.Entry<String, ClientMappingsRepresentation> clientRoleMapping : mapping.entrySet()) {
                for (RoleRepresentation role : clientRoleMapping.getValue().getMappings()) {
                    allRoles.add(clientRoleMapping.getKey() + ":" + role.getName());
                }
            }
        }
        return toReturn;
    }

    /**
     * Get the list of default realm, and client roles from the Keycloak server
     *
     * TODO: Doesn't really work. Asking in keycloak forum for help:
     * https://keycloak.discourse.group/t/find-default-realm-roles-using-keycloak-admin-client/9350
     *
     * @return list of default realm, and client roles
     */
    public Set<String> getDefaultRoles() {

        Set<String> defaultRoles = new HashSet<>();

        // Get all default realm role
        Optional<RealmRepresentation> realmRepresentation = keycloak.realms()
                .findAll()
                .stream()
                .filter(r -> r.getRealm().equals(this.realm))
                .findFirst();

        if (realmRepresentation.isPresent()) {

            defaultRoles.addAll(realmRepresentation.get().getDefaultRoles());
            List<ClientRepresentation> clients = realmRepresentation.get().getClients();

            for (ClientRepresentation client : clients) {
                for (String clientRole : client.getDefaultRoles()) {
                    defaultRoles.add(client.getName() + ":" + clientRole);
                }
            }
        }

        return defaultRoles;
    }
}
