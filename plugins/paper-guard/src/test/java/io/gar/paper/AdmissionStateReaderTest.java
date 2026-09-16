package io.gar.paper;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class AdmissionStateReaderTest {
    private static final Instant NOW = Instant.parse("2026-09-16T12:00:00Z");

    @TempDir
    Path directory;

    @Test
    void acceptsOnlyFreshBoundedOpenLease() throws Exception {
        Path state = writeState("""
                {"schema_version":"gar.admission-state.v1","pairing_id":"pairing-0123456789",
                "deployment_generation":3,"mode":"OPEN","reason":"test",
                "issued_at":"2026-09-16T11:59:55Z","expires_at":"2026-09-16T12:00:20Z"}
                """);
        AdmissionDecision decision = new AdmissionStateReader(state, "pairing-0123456789", 3).read(NOW);
        assertTrue(decision.open());
        assertTrue(decision.runtimeState().equals("OPEN_READ_ONLY_ALPHA"));
    }

    @Test
    void failsClosedForExpiredDuplicateAndUnsafeState() throws Exception {
        Path state = writeState("""
                {"schema_version":"gar.admission-state.v1","pairing_id":"pairing-0123456789",
                "deployment_generation":3,"mode":"OPEN","reason":"expired",
                "issued_at":"2026-09-16T11:59:00Z","expires_at":"2026-09-16T11:59:30Z"}
                """);
        AdmissionStateReader reader = new AdmissionStateReader(state, "pairing-0123456789", 3);
        assertFalse(reader.read(NOW).open());

        Files.writeString(state, """
                {"schema_version":"gar.admission-state.v1","pairing_id":"pairing-0123456789",
                "deployment_generation":3,"mode":"CLOSED","mode":"OPEN","reason":"duplicate",
                "issued_at":"2026-09-16T12:00:00Z","expires_at":"2026-09-16T12:00:20Z"}
                """);
        assertFalse(reader.read(NOW).open());

        Files.setPosixFilePermissions(state, PosixFilePermissions.fromString("rw-r--r--"));
        assertFalse(reader.read(NOW).open());
    }

    @Test
    void failsClosedForMissingOrCrossGenerationState() throws Exception {
        Path missing = directory.resolve("missing.json").toAbsolutePath().normalize();
        assertFalse(new AdmissionStateReader(missing, "pairing-0123456789", 3).read(NOW).open());

        Path state = writeState("""
                {"schema_version":"gar.admission-state.v1","pairing_id":"pairing-0123456789",
                "deployment_generation":2,"mode":"OPEN","reason":"wrong generation",
                "issued_at":"2026-09-16T12:00:00Z","expires_at":"2026-09-16T12:00:20Z"}
                """);
        assertFalse(new AdmissionStateReader(state, "pairing-0123456789", 3).read(NOW).open());
    }

    @Test
    void loginPolicyRejectsEveryClosedDecision() {
        assertTrue(GarGuardPlugin.shouldRejectLogin(AdmissionDecision.closed("ADMISSION_STATE_MISSING")));
        assertTrue(GarGuardPlugin.shouldRejectLogin(AdmissionDecision.closed("ADMISSION_STATE_INVALID")));
        assertFalse(GarGuardPlugin.shouldRejectLogin(new AdmissionDecision(true, "ADMISSION_OPEN")));
    }

    @Test
    void loginGuardRunsAtHighestPriority() throws Exception {
        EventHandler annotation = GarGuardPlugin.class
                .getDeclaredMethod("onAsyncPlayerPreLogin", AsyncPlayerPreLoginEvent.class)
                .getAnnotation(EventHandler.class);
        assertEquals(EventPriority.HIGHEST, annotation.priority());
    }

    private Path writeState(String payload) throws Exception {
        Path state = directory.resolve("state.json").toAbsolutePath().normalize();
        Files.writeString(state, payload);
        Files.setPosixFilePermissions(state, PosixFilePermissions.fromString("rw-------"));
        return state;
    }
}
