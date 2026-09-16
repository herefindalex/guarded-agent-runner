package io.gar.paper;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

final class SnapshotJsonTest {
    @Test
    void escapesUntrustedPluginDescriptorText() {
        RuntimeSnapshot snapshot = new RuntimeSnapshot(
                RuntimeSnapshot.SCHEMA_VERSION, "pairing-0123456789", "boot-a",
                Instant.parse("2026-09-16T10:00:00Z"), true, "OPEN_READ_ONLY_ALPHA",
                0, new double[] {20.0, Double.NaN}, 12.5, 10, 20,
                List.of(new PluginObservation("evil\n\"plugin", "1.0", true, "UNAVAILABLE")));
        String json = SnapshotJson.encode(snapshot);
        assertTrue(json.contains("evil\\n\\\"plugin"));
        assertTrue(json.contains("[20.000,null]"));
        assertFalse(json.contains("evil\n\"plugin"));
    }

    @Test
    void rejectsPathEscapeForSnapshotFile() {
        assertThrows(IllegalArgumentException.class,
                () -> new AtomicSnapshotPublisher(Path.of("."), "../observation.json"));
        assertThrows(IllegalArgumentException.class,
                () -> new AtomicSnapshotPublisher(Path.of("."), "/tmp/observation.json"));
    }
}
