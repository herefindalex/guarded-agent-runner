package io.gar.paper;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import net.kyori.adventure.text.Component;
import org.bukkit.Bukkit;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

public final class GarGuardPlugin extends JavaPlugin implements Listener {
    private static final String PAIRING_PLACEHOLDER = "REQUIRED_CHANGE_ME";

    private final String bootId = UUID.randomUUID().toString();
    private final AtomicBoolean writeInProgress = new AtomicBoolean();
    private AtomicSnapshotPublisher publisher;
    private AdmissionStateReader admissionReader;
    private String pairingId;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        pairingId = getConfig().getString("pairing-id", PAIRING_PLACEHOLDER).trim();
        if (pairingId.equals(PAIRING_PLACEHOLDER) || pairingId.length() < 16 || pairingId.length() > 128) {
            getLogger().severe("GARGuard pairing-id is unset or invalid; disabling fail-closed");
            Bukkit.getPluginManager().disablePlugin(this);
            return;
        }
        String snapshotFile = getConfig().getString("snapshot-file", "runtime-observation.json");
        try {
            publisher = new AtomicSnapshotPublisher(getDataFolder().toPath(), snapshotFile);
            String admissionPath = getConfig().getString("admission-state-file", "").trim();
            if (!admissionPath.isEmpty()) {
                long deploymentGeneration = getConfig().getLong("deployment-generation", 0L);
                admissionReader = new AdmissionStateReader(Path.of(admissionPath), pairingId, deploymentGeneration);
                Bukkit.getPluginManager().registerEvents(this, this);
            }
        } catch (IllegalArgumentException error) {
            getLogger().log(Level.SEVERE, "GARGuard fixed configuration is unsafe; disabling", error);
            Bukkit.getPluginManager().disablePlugin(this);
            return;
        }
        Bukkit.getScheduler().runTaskTimer(this, this::captureAndPublish, 1L, 20L);
        if (admissionReader == null) {
            getLogger().info("GARGuard runtime observation enabled without admission enforcement");
        } else {
            getLogger().info("GARGuard runtime observation and fail-closed login admission enabled");
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onAsyncPlayerPreLogin(AsyncPlayerPreLoginEvent event) {
        AdmissionDecision decision = currentAdmissionDecision();
        if (shouldRejectLogin(decision)) {
            event.disallow(
                    AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    Component.text("Server maintenance is active; admission is closed."));
        }
    }

    static boolean shouldRejectLogin(AdmissionDecision decision) {
        return !decision.open();
    }

    @Override
    public void onDisable() {
        if (publisher == null || pairingId == null || pairingId.equals(PAIRING_PLACEHOLDER)) {
            return;
        }
        try {
            publisher.publish(capture(false));
        } catch (Exception error) {
            getLogger().log(Level.WARNING, "Could not publish final unavailable runtime snapshot", error);
        }
    }

    private void captureAndPublish() {
        RuntimeSnapshot snapshot = capture(true);
        if (!writeInProgress.compareAndSet(false, true)) {
            return;
        }
        Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
            try {
                publisher.publish(snapshot);
            } catch (Exception error) {
                getLogger().log(Level.WARNING, "Could not atomically publish runtime observation", error);
            } finally {
                writeInProgress.set(false);
            }
        });
    }

    private RuntimeSnapshot capture(boolean ready) {
        Plugin[] loaded = Bukkit.getPluginManager().getPlugins();
        List<PluginObservation> plugins = Arrays.stream(loaded)
                .sorted(Comparator.comparing(Plugin::getName))
                .map(plugin -> new PluginObservation(
                        plugin.getName(),
                        plugin.getPluginMeta().getVersion(),
                        plugin.isEnabled(),
                        "UNAVAILABLE"))
                .toList();
        Runtime runtime = Runtime.getRuntime();
        return new RuntimeSnapshot(
                RuntimeSnapshot.SCHEMA_VERSION,
                pairingId,
                bootId,
                Instant.now(),
                ready,
                currentAdmissionDecision().runtimeState(),
                Bukkit.getOnlinePlayers().size(),
                Bukkit.getTPS().clone(),
                Bukkit.getAverageTickTime(),
                runtime.totalMemory() - runtime.freeMemory(),
                runtime.maxMemory(),
                plugins);
    }

    private AdmissionDecision currentAdmissionDecision() {
        if (admissionReader == null) {
            return new AdmissionDecision(true, "ADMISSION_NOT_CONFIGURED_READ_ONLY");
        }
        return admissionReader.read(Instant.now());
    }
}
