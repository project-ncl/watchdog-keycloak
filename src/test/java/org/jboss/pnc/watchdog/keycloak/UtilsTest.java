package org.jboss.pnc.watchdog.keycloak;

import static org.assertj.core.api.Assertions.*;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

class UtilsTest {

    @Test
    void testSuccessCompareRoles() {
        List<String> currentRoles = List.of("user", "admin", "client:role");
        List<String> allowedRoles = List.of("user", "client:role*");
        List<String> deniedRoles = List.of("client:admin", "dangerous");

        boolean success = Utils.compareRoles(currentRoles, allowedRoles, deniedRoles);
        assertThat(success).isTrue();
    }

    @Test
    void testFailedAllowedCompareRoles() {
        List<String> currentRoles = List.of("user", "admin", "client:role");
        List<String> allowedRoles = List.of("user", "client:role*", "should_also_be_present");
        List<String> deniedRoles = List.of("client:admin", "dangerous");

        boolean success = Utils.compareRoles(currentRoles, allowedRoles, deniedRoles);
        assertThat(success).isFalse();
    }

    @Test
    void testFailedDeniedCompareRoles() {
        List<String> currentRoles = List.of("user", "admin", "client:role");
        List<String> allowedRoles = List.of("user");
        List<String> deniedRoles = List.of("client:rol*", "dangerous");

        boolean success = Utils.compareRoles(currentRoles, allowedRoles, deniedRoles);
        assertThat(success).isFalse();
    }

    @Test
    void testFailedCompareRoles() {
        List<String> currentRoles = List.of("user", "dangerous");
        List<String> allowedRoles = List.of("user", "admin");
        List<String> deniedRoles = List.of("dangerous");

        boolean success = Utils.compareRoles(currentRoles, allowedRoles, deniedRoles);
        assertThat(success).isFalse();
    }

    @Test
    void testRegexCompareRoles() {
        List<String> currentRoles = List.of("admin:bool", "dangerous");
        List<String> deniedRoles = List.of("admin:*");

        boolean success = Utils.compareRoles(currentRoles, Collections.emptyList(), deniedRoles);
        assertThat(success).isFalse();

        List<String> deniedRoles2 = List.of("not-so-dangerous");
        List<String> allowedRoles = List.of("dan*");

        boolean success2 = Utils.compareRoles(currentRoles, allowedRoles, deniedRoles2);
        assertThat(success2).isTrue();
    }
}
