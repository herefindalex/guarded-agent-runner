package io.gar.paper;

import java.time.Instant;
import java.util.List;

record RuntimeSnapshot(
        String schemaVersion,
        String pairingId,
        String bootId,
        Instant observedAt,
        boolean ready,
        String admissionState,
        int playerCount,
        double[] tps,
        double mspt,
        long heapUsedBytes,
        long heapMaxBytes,
        List<PluginObservation> plugins) {

    static final String SCHEMA_VERSION = "gar.paper-runtime-observation.v1";
}

record PluginObservation(String name, String version, boolean enabled, String sourceAttribution) {}
