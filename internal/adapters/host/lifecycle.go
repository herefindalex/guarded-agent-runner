package host

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LifecycleEvidence is a bounded Docker lifecycle observation for the one
// container fixed in ObserverConfig. It carries no caller-selected target.
type LifecycleEvidence struct {
	ContainerID string
	Status      string
	Running     bool
	OOMKilled   bool
	ExitCode    int
	StartedAt   time.Time
	FinishedAt  time.Time
	ObservedAt  time.Time
}

func (observer *Observer) ObserveLifecycle(ctx context.Context) (LifecycleEvidence, error) {
	inspection, err := observer.inspectContainer(ctx)
	if err != nil {
		return LifecycleEvidence{}, err
	}
	if inspection.ID != observer.config.ContainerID {
		return LifecycleEvidence{}, fmt.Errorf("container ID mismatch")
	}
	started, err := parseDockerTime(inspection.State.StartedAt)
	if err != nil {
		return LifecycleEvidence{}, fmt.Errorf("invalid container start time: %w", err)
	}
	finished, err := parseDockerTime(inspection.State.FinishedAt)
	if err != nil {
		return LifecycleEvidence{}, fmt.Errorf("invalid container finish time: %w", err)
	}
	return LifecycleEvidence{
		ContainerID: inspection.ID,
		Status:      inspection.State.Status,
		Running:     inspection.State.Running,
		OOMKilled:   inspection.State.OOMKilled,
		ExitCode:    inspection.State.ExitCode,
		StartedAt:   started,
		FinishedAt:  finished,
		ObservedAt:  observer.now().UTC(),
	}, nil
}

func parseDockerTime(value string) (time.Time, error) {
	if value == "" || strings.HasPrefix(value, "0001-01-01") {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, value)
}

// StopContainer asks Docker to stop only the enrolled container. A successful
// response means the request was acknowledged; callers must still establish
// the effect through ObserveLifecycle, terminal runtime evidence and logs.
func (observer *Observer) StopContainer(ctx context.Context, timeout time.Duration) error {
	seconds := int(timeout.Round(time.Second) / time.Second)
	if seconds < 1 || seconds > 120 {
		return fmt.Errorf("stop timeout must be from 1 through 120 seconds")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://docker/containers/"+observer.config.ContainerID+"/stop?t="+strconv.Itoa(seconds), nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: observer.client.Transport, Timeout: timeout + 5*time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Docker stop returned status %d", response.StatusCode)
	}
	return nil
}

// GracefulStopLogEvidence reads only bounded logs for the enrolled container
// since dispatch. The three markers cover Paper shutdown, world persistence
// and the itzg runner's clean terminal state.
func (observer *Observer) GracefulStopLogEvidence(ctx context.Context, since time.Time) ([]string, error) {
	query := url.Values{}
	query.Set("stdout", "1")
	query.Set("stderr", "1")
	query.Set("timestamps", "1")
	// The Docker Engine logs endpoint accepts an integer Unix timestamp here.
	// Request the containing second, then enforce the exact nanosecond boundary
	// against each timestamped log line below.
	query.Set("since", strconv.FormatInt(since.Unix(), 10))
	query.Set("tail", "1000")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://docker/containers/"+observer.config.ContainerID+"/logs?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	response, err := observer.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Docker logs returned status %d", response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(payload) > 1<<20 {
		return nil, fmt.Errorf("bounded shutdown logs unavailable")
	}
	return gracefulStopReferences(payload, since)
}

func gracefulStopReferences(payload []byte, since time.Time) ([]string, error) {
	text, err := dockerLogText(payload)
	if err != nil {
		return nil, err
	}
	markers := []struct {
		name  string
		match string
	}{
		{"paper-stop", "Stopping server"},
		{"worlds-saved", "All dimensions are saved"},
		{"runner-done", "mc-server-runner\tDone"},
	}
	references := make([]string, 0, len(markers))
	found := make(map[string]bool, len(markers))
	scanner := bufio.NewScanner(bytes.NewReader(text))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		separator := strings.IndexByte(line, ' ')
		if separator < 1 {
			continue
		}
		observedAt, parseErr := time.Parse(time.RFC3339Nano, line[:separator])
		if parseErr != nil || observedAt.Before(since) {
			continue
		}
		for _, marker := range markers {
			if strings.Contains(line[separator+1:], marker.match) {
				found[marker.name] = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan bounded shutdown logs: %w", err)
	}
	for _, marker := range markers {
		if !found[marker.name] {
			return nil, fmt.Errorf("shutdown log marker %q unavailable", marker.name)
		}
		references = append(references, "docker-log:"+marker.name)
	}
	return references, nil
}

// dockerLogText removes Docker's stdcopy framing when TTY is disabled. TTY
// containers return plain text, which is accepted unchanged.
func dockerLogText(payload []byte) ([]byte, error) {
	if len(payload) == 0 || (payload[0] != 1 && payload[0] != 2) {
		return payload, nil
	}
	var output bytes.Buffer
	for len(payload) > 0 {
		if len(payload) < 8 || payload[1] != 0 || payload[2] != 0 || payload[3] != 0 {
			return nil, fmt.Errorf("invalid Docker log stream framing")
		}
		size := int(binary.BigEndian.Uint32(payload[4:8]))
		if size < 0 || size > len(payload)-8 {
			return nil, fmt.Errorf("invalid Docker log frame size")
		}
		output.Write(payload[8 : 8+size])
		payload = payload[8+size:]
	}
	return output.Bytes(), nil
}

// ManagedPluginSource resolves the exact fixed plugin slot through the
// enrolled container mounts. A bind-mounted source remains part of the
// enrolled target even though the host data-root mount point is overlaid in
// the container.
func (observer *Observer) ManagedPluginSource(ctx context.Context, pluginID string) (logicalPath, sourcePath string, err error) {
	fileName, ok := observer.config.ManagedPluginSlots[pluginID]
	if !ok {
		return "", "", fmt.Errorf("plugin is not in the enrolled managed slots")
	}
	inspection, err := observer.inspectContainer(ctx)
	if err != nil {
		return "", "", err
	}
	if inspection.ID != observer.config.ContainerID {
		return "", "", fmt.Errorf("container ID mismatch")
	}
	logicalPath = filepath.ToSlash(filepath.Join("plugins", fileName))
	for _, mount := range inspection.Mounts {
		if mount.Destination != "/data/plugins/"+fileName {
			continue
		}
		if mount.Type != "bind" || mount.RW {
			return "", "", fmt.Errorf("managed plugin mount is not a read-only bind")
		}
		resolved, resolveErr := filepath.EvalSymlinks(mount.Source)
		if resolveErr != nil || resolved != mount.Source {
			return "", "", fmt.Errorf("managed plugin source is unavailable or traverses a symlink")
		}
		return logicalPath, mount.Source, nil
	}
	return logicalPath, filepath.Join(observer.config.DataRootPath, filepath.FromSlash(logicalPath)), nil
}
