package io.gar.paper;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

final class AdmissionStateReader {
    static final String SCHEMA_VERSION = "gar.admission-state.v1";
    private static final long MAX_BYTES = 64L * 1024L;
    private static final Duration MAX_LEASE = Duration.ofSeconds(30);

    private final Path path;
    private final String pairingId;
    private final long deploymentGeneration;

    AdmissionStateReader(Path path, String pairingId, long deploymentGeneration) {
        if (!path.isAbsolute() || !path.normalize().equals(path)) {
            throw new IllegalArgumentException("admission state path must be clean and absolute");
        }
        if (deploymentGeneration < 1) {
            throw new IllegalArgumentException("deployment generation must be positive");
        }
        this.path = path;
        this.pairingId = pairingId;
        this.deploymentGeneration = deploymentGeneration;
    }

    AdmissionDecision read(Instant now) {
        try {
            if (Files.isSymbolicLink(path)) {
                return AdmissionDecision.closed("ADMISSION_STATE_SYMLINK");
            }
            BasicFileAttributes attributes = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isRegularFile() || attributes.size() > MAX_BYTES) {
                return AdmissionDecision.closed("ADMISSION_STATE_INVALID_FILE");
            }
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
            if (permissions.contains(PosixFilePermission.GROUP_READ)
                    || permissions.contains(PosixFilePermission.GROUP_WRITE)
                    || permissions.contains(PosixFilePermission.GROUP_EXECUTE)
                    || permissions.contains(PosixFilePermission.OTHERS_READ)
                    || permissions.contains(PosixFilePermission.OTHERS_WRITE)
                    || permissions.contains(PosixFilePermission.OTHERS_EXECUTE)) {
                return AdmissionDecision.closed("ADMISSION_STATE_UNSAFE_PERMISSIONS");
            }
            String payload = Files.readString(path, StandardCharsets.UTF_8);
            return parse(payload, now);
        } catch (Exception error) {
            return AdmissionDecision.closed("ADMISSION_STATE_UNAVAILABLE");
        }
    }

    private AdmissionDecision parse(String payload, Instant now) throws Exception {
        String schemaVersion = null;
        String observedPairing = null;
        Long observedGeneration = null;
        String mode = null;
        String reason = null;
        Instant issuedAt = null;
        Instant expiresAt = null;
        Set<String> names = new HashSet<>();

        try (JsonReader reader = new JsonReader(new StringReader(payload))) {
            reader.setLenient(false);
            reader.beginObject();
            while (reader.hasNext()) {
                String name = reader.nextName();
                if (!names.add(name)) {
                    return AdmissionDecision.closed("ADMISSION_STATE_DUPLICATE_FIELD");
                }
                switch (name) {
                    case "schema_version" -> schemaVersion = reader.nextString();
                    case "pairing_id" -> observedPairing = reader.nextString();
                    case "deployment_generation" -> observedGeneration = reader.nextLong();
                    case "mode" -> mode = reader.nextString();
                    case "reason" -> reason = reader.nextString();
                    case "issued_at" -> issuedAt = Instant.parse(reader.nextString());
                    case "expires_at" -> expiresAt = Instant.parse(reader.nextString());
                    default -> {
                        return AdmissionDecision.closed("ADMISSION_STATE_UNKNOWN_FIELD");
                    }
                }
            }
            reader.endObject();
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                return AdmissionDecision.closed("ADMISSION_STATE_TRAILING_DATA");
            }
        }

        if (!SCHEMA_VERSION.equals(schemaVersion)
                || !pairingId.equals(observedPairing)
                || observedGeneration == null
                || observedGeneration != deploymentGeneration
                || issuedAt == null
                || issuedAt.isAfter(now.plusSeconds(2))
                || reason == null
                || reason.length() > 256) {
            return AdmissionDecision.closed("ADMISSION_STATE_IDENTITY_OR_SCHEMA_MISMATCH");
        }
        if ("CLOSED".equals(mode)) {
            return AdmissionDecision.closed("ADMISSION_CLOSED");
        }
        if (!"OPEN".equals(mode)
                || expiresAt == null
                || !expiresAt.isAfter(now)
                || !expiresAt.isAfter(issuedAt)
                || Duration.between(issuedAt, expiresAt).compareTo(MAX_LEASE) > 0) {
            return AdmissionDecision.closed("ADMISSION_LEASE_INVALID_OR_EXPIRED");
        }
        return new AdmissionDecision(true, "ADMISSION_OPEN");
    }
}

record AdmissionDecision(boolean open, String reasonCode) {
    static AdmissionDecision closed(String reasonCode) {
        return new AdmissionDecision(false, reasonCode);
    }

    String runtimeState() {
        return open ? "OPEN_READ_ONLY_ALPHA" : "MAINTENANCE";
    }
}
