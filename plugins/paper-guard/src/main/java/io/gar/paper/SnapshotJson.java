package io.gar.paper;

import java.util.Locale;

final class SnapshotJson {
    private SnapshotJson() {}

    static String encode(RuntimeSnapshot snapshot) {
        StringBuilder json = new StringBuilder(2048);
        json.append('{');
        field(json, "schema_version", snapshot.schemaVersion()).append(',');
        field(json, "pairing_id", snapshot.pairingId()).append(',');
        field(json, "boot_id", snapshot.bootId()).append(',');
        field(json, "observed_at", snapshot.observedAt().toString()).append(',');
        json.append("\"ready\":").append(snapshot.ready()).append(',');
        field(json, "admission_state", snapshot.admissionState()).append(',');
        json.append("\"player_count\":").append(snapshot.playerCount()).append(',');
        json.append("\"tps\":[");
        for (int index = 0; index < snapshot.tps().length; index++) {
            if (index > 0) json.append(',');
            number(json, snapshot.tps()[index]);
        }
        json.append("],\"mspt\":");
        number(json, snapshot.mspt());
        json.append(",\"heap_used_bytes\":").append(snapshot.heapUsedBytes());
        json.append(",\"heap_max_bytes\":").append(snapshot.heapMaxBytes());
        json.append(",\"plugins\":[");
        for (int index = 0; index < snapshot.plugins().size(); index++) {
            if (index > 0) json.append(',');
            PluginObservation plugin = snapshot.plugins().get(index);
            json.append('{');
            field(json, "name", plugin.name()).append(',');
            field(json, "version", plugin.version()).append(',');
            json.append("\"enabled\":").append(plugin.enabled()).append(',');
            field(json, "source_attribution", plugin.sourceAttribution());
            json.append('}');
        }
        return json.append("]}").toString();
    }

    private static StringBuilder field(StringBuilder json, String name, String value) {
        return json.append('"').append(name).append("\":\"").append(escape(value)).append('"');
    }

    private static void number(StringBuilder json, double value) {
        if (!Double.isFinite(value)) {
            json.append("null");
            return;
        }
        json.append(String.format(Locale.ROOT, "%.3f", value));
    }

    static String escape(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 16);
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (character < 0x20 || Character.isSurrogate(character)) {
                        escaped.append(String.format(Locale.ROOT, "\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
                }
            }
        }
        return escaped.toString();
    }
}
