package host

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestGracefulStopLogEvidenceUsesDockerCompatibleSince(t *testing.T) {
	since := time.Date(2026, 9, 17, 12, 51, 36, 17_952_650, time.UTC)
	payload := dockerLogFrame(1, []byte(
		"2026-09-17T12:51:36.183717203Z Stopping server\n"+
			"2026-09-17T12:51:36.457448605Z ThreadedAnvilChunkStorage: All dimensions are saved\n"+
			"2026-09-17T12:51:37.219366961Z mc-server-runner\tDone\n",
	))
	observer := &Observer{
		config: ObserverConfig{ContainerID: "fixed-container"},
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if got, want := request.URL.Query().Get("since"), strconv.FormatInt(since.Unix(), 10); got != want {
				t.Fatalf("Docker logs since = %q, want integer %q", got, want)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(payload)),
				Header:     make(http.Header),
				Request:    request,
			}, nil
		})},
	}

	references, err := observer.GracefulStopLogEvidence(t.Context(), since)
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != 3 {
		t.Fatalf("got %d references, want 3", len(references))
	}
}

func TestDockerLogTextDecodesMultiplexedFrames(t *testing.T) {
	first := []byte("2026-09-17T12:51:36.183717203Z Stopping server\n")
	second := []byte("2026-09-17T12:51:37.219366961Z mc-server-runner\tDone\n")
	payload := append(dockerLogFrame(1, first), dockerLogFrame(2, second)...)

	got, err := dockerLogText(payload)
	if err != nil {
		t.Fatal(err)
	}
	want := string(first) + string(second)
	if string(got) != want {
		t.Fatalf("decoded logs = %q, want %q", got, want)
	}
}

func TestDockerLogTextRejectsMalformedFrame(t *testing.T) {
	payload := dockerLogFrame(1, []byte("short"))
	binary.BigEndian.PutUint32(payload[4:8], uint32(len(payload)))
	if _, err := dockerLogText(payload); err == nil {
		t.Fatal("malformed Docker log frame was accepted")
	}
}

func TestGracefulStopReferencesEnforcesExactDispatchTime(t *testing.T) {
	since := time.Date(2026, 9, 17, 12, 51, 36, 17_952_650, time.UTC)
	before := "2026-09-17T12:51:36.000000000Z "
	after := "2026-09-17T12:51:36.183717203Z "
	payload := dockerLogFrame(1, []byte(
		before+"Stopping server\n"+
			after+"ThreadedAnvilChunkStorage: All dimensions are saved\n"+
			"2026-09-17T12:51:37.219366961Z mc-server-runner\tDone\n",
	))
	if _, err := gracefulStopReferences(payload, since); err == nil {
		t.Fatal("pre-dispatch shutdown marker was accepted")
	}

	payload = dockerLogFrame(1, []byte(
		after+"Stopping server\n"+
			after+"ThreadedAnvilChunkStorage: All dimensions are saved\n"+
			"2026-09-17T12:51:37.219366961Z mc-server-runner\tDone\n",
	))
	references, err := gracefulStopReferences(payload, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != 3 {
		t.Fatalf("got %d references, want 3", len(references))
	}
}

func TestObserveLifecycleReturnsExactDockerState(t *testing.T) {
	started := "2026-09-17T12:50:00.123456789Z"
	finished := "2026-09-17T12:51:37.219366961Z"
	inspection := dockerInspection{ID: "fixed-container"}
	inspection.State.Status = "exited"
	inspection.State.ExitCode = 0
	inspection.State.StartedAt = started
	inspection.State.FinishedAt = finished
	observedAt := time.Date(2026, 9, 17, 12, 51, 38, 0, time.UTC)
	observer := &Observer{
		config: ObserverConfig{ContainerID: "fixed-container"},
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			payload, err := json.Marshal(inspection)
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(payload)), Header: make(http.Header), Request: request}, nil
		})},
		now: func() time.Time { return observedAt },
	}

	evidence, err := observer.ObserveLifecycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if evidence.ContainerID != inspection.ID || evidence.Status != "exited" || evidence.Running ||
		evidence.ExitCode != 0 || evidence.OOMKilled || evidence.ObservedAt != observedAt {
		t.Fatalf("lifecycle evidence lost Docker state: %#v", evidence)
	}
	wantStarted, _ := time.Parse(time.RFC3339Nano, started)
	wantFinished, _ := time.Parse(time.RFC3339Nano, finished)
	if !evidence.StartedAt.Equal(wantStarted) || !evidence.FinishedAt.Equal(wantFinished) {
		t.Fatalf("lifecycle timestamps changed: %#v", evidence)
	}

	inspection.State.StartedAt = "not-a-time"
	if _, err := observer.ObserveLifecycle(context.Background()); err == nil {
		t.Fatal("invalid Docker lifecycle timestamp was accepted")
	}
}

func TestStopContainerUsesOnlyEnrolledContainerAndBoundedTimeout(t *testing.T) {
	requests := 0
	observer := &Observer{
		config: ObserverConfig{ContainerID: "fixed-container"},
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests++
			if request.Method != http.MethodPost || request.URL.Path != "/containers/fixed-container/stop" || request.URL.Query().Get("t") != "30" {
				t.Fatalf("unexpected stop request: %s %s", request.Method, request.URL.String())
			}
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header), Request: request}, nil
		})},
	}
	if err := observer.StopContainer(context.Background(), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("stop requests = %d, want 1", requests)
	}
	for _, timeout := range []time.Duration{0, 121 * time.Second} {
		if err := observer.StopContainer(context.Background(), timeout); err == nil {
			t.Fatalf("unsafe timeout %s was accepted", timeout)
		}
	}
}

func TestManagedPluginSourcePinsReadonlyBind(t *testing.T) {
	source := filepath.Join(t.TempDir(), "GARGuard.jar")
	if err := os.WriteFile(source, []byte("plugin"), 0o600); err != nil {
		t.Fatal(err)
	}
	inspection := dockerInspection{ID: "fixed-container", Mounts: []dockerMount{{
		Type: "bind", Source: source, Destination: "/data/plugins/GARGuard.jar", RW: false,
	}}}
	observer := &Observer{
		config: ObserverConfig{
			ContainerID: "fixed-container", DataRootPath: "/fixed/data",
			ManagedPluginSlots: map[string]string{"gar-guard": "GARGuard.jar"},
		},
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			payload, err := json.Marshal(inspection)
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(payload)), Header: make(http.Header), Request: request}, nil
		})},
	}
	logical, resolved, err := observer.ManagedPluginSource(context.Background(), "gar-guard")
	if err != nil {
		t.Fatal(err)
	}
	if logical != "plugins/GARGuard.jar" || resolved != source {
		t.Fatalf("managed source = %q %q", logical, resolved)
	}
	if _, _, err := observer.ManagedPluginSource(context.Background(), "other"); err == nil {
		t.Fatal("unenrolled plugin slot was accepted")
	}
	inspection.Mounts[0].RW = true
	if _, _, err := observer.ManagedPluginSource(context.Background(), "gar-guard"); err == nil {
		t.Fatal("writable managed plugin bind was accepted")
	}
}

func dockerLogFrame(stream byte, payload []byte) []byte {
	frame := make([]byte, 8+len(payload))
	frame[0] = stream
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload)))
	copy(frame[8:], payload)
	return frame
}
