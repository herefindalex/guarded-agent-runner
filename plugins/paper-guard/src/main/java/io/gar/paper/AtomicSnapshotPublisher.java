package io.gar.paper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

final class AtomicSnapshotPublisher {
    private static final Pattern SAFE_FILE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    private static final Set<PosixFilePermission> OWNER_GROUP_READ = Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.GROUP_READ);

    private final Path directory;
    private final String fileName;

    AtomicSnapshotPublisher(Path directory, String fileName) {
        if (!SAFE_FILE.matcher(fileName).matches() || fileName.equals(".") || fileName.equals("..")) {
            throw new IllegalArgumentException("snapshot-file must be a bounded basename");
        }
        this.directory = directory.toAbsolutePath().normalize();
        this.fileName = fileName;
    }

    Path destination() {
        return directory.resolve(fileName);
    }

    void publish(RuntimeSnapshot snapshot) throws IOException {
        Files.createDirectories(directory);
        Path temporary = directory.resolve("." + fileName + "." + UUID.randomUUID() + ".tmp");
        byte[] payload = (SnapshotJson.encode(snapshot) + "\n").getBytes(StandardCharsets.UTF_8);
        try {
            try (FileChannel channel = FileChannel.open(temporary,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                channel.write(ByteBuffer.wrap(payload));
                channel.force(true);
            }
            try {
                Files.setPosixFilePermissions(temporary, OWNER_GROUP_READ);
            } catch (UnsupportedOperationException ignored) {
                // The supported reference deployment is Linux. Tests may run
                // on a filesystem without POSIX permissions.
            }
            try {
                Files.move(temporary, destination(), StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException error) {
                throw new IOException("snapshot filesystem does not support atomic publication", error);
            }
            try (FileChannel directoryChannel = FileChannel.open(directory, StandardOpenOption.READ)) {
                directoryChannel.force(true);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }
}
