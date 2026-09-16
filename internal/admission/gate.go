package admission

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type Gate struct {
	config Config
	now    func() time.Time
	log    io.Writer

	mu             sync.Mutex
	connections    map[net.Conn]struct{}
	activeSessions int
}

func NewGate(config Config, log io.Writer) (*Gate, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = io.Discard
	}
	return &Gate{
		config: config, now: time.Now, log: log,
		connections: make(map[net.Conn]struct{}),
	}, nil
}

func (gate *Gate) SetClockForTest(now func() time.Time) { gate.now = now }

func (gate *Gate) Run(ctx context.Context) error {
	listeners := make([]net.Listener, 0, len(gate.config.ListenAddresses))
	for _, address := range gate.config.ListenAddresses {
		listener, err := net.Listen(networkFor(address), address)
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return fmt.Errorf("listen on fixed admission address %s: %w", address, err)
		}
		listeners = append(listeners, listener)
	}

	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
		gate.closeAll()
	}()

	go func() {
		<-runContext.Done()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		gate.closeAll()
	}()
	go gate.monitor(runContext)

	decision := EvaluateAccess(gate.config, gate.now().UTC())
	fmt.Fprintf(gate.log, "admission barrier started state=%s listeners=%d\n", decision.ReasonCode, len(listeners))
	if !decision.Open {
		gate.closeAll()
	}

	errCh := make(chan error, len(listeners))
	for _, listener := range listeners {
		go gate.accept(runContext, listener, errCh)
	}
	select {
	case <-runContext.Done():
		return nil
	case err := <-errCh:
		cancel()
		return err
	}
}

func (gate *Gate) monitor(ctx context.Context) {
	ticker := time.NewTicker(gate.config.PollInterval())
	defer ticker.Stop()
	lastReason := ""
	for {
		decision := EvaluateAccess(gate.config, gate.now().UTC())
		if decision.ReasonCode != lastReason {
			fmt.Fprintf(gate.log, "admission state=%s\n", decision.ReasonCode)
			lastReason = decision.ReasonCode
		}
		if !decision.Open {
			gate.closeAll()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (gate *Gate) accept(ctx context.Context, listener net.Listener, errCh chan<- error) {
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			select {
			case errCh <- fmt.Errorf("admission accept failed: %w", err):
			default:
			}
			return
		}
		go gate.handle(ctx, client)
	}
}

func (gate *Gate) handle(ctx context.Context, client net.Conn) {
	if !gate.startSession(client) {
		_ = client.Close()
		return
	}
	defer gate.endSession(client)

	decision := EvaluateAccess(gate.config, gate.now().UTC())
	if !decision.Open {
		return
	}
	dialer := net.Dialer{Timeout: gate.config.DialTimeout()}
	upstream, err := dialer.DialContext(ctx, networkFor(gate.config.UpstreamAddress), gate.config.UpstreamAddress)
	if err != nil {
		return
	}
	gate.track(upstream)
	defer gate.untrack(upstream)
	defer upstream.Close()

	done := make(chan struct{}, 2)
	copyStream := func(destination net.Conn, source net.Conn) {
		_, _ = io.Copy(destination, source)
		done <- struct{}{}
	}
	go copyStream(upstream, client)
	go copyStream(client, upstream)
	select {
	case <-ctx.Done():
	case <-done:
	}
	_ = client.Close()
	_ = upstream.Close()
}

func (gate *Gate) startSession(connection net.Conn) bool {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.activeSessions >= gate.config.MaxConnections {
		return false
	}
	gate.activeSessions++
	gate.connections[connection] = struct{}{}
	return true
}

func (gate *Gate) endSession(connection net.Conn) {
	gate.mu.Lock()
	delete(gate.connections, connection)
	gate.activeSessions--
	gate.mu.Unlock()
	_ = connection.Close()
}

func (gate *Gate) track(connection net.Conn) {
	gate.mu.Lock()
	gate.connections[connection] = struct{}{}
	gate.mu.Unlock()
}

func (gate *Gate) untrack(connection net.Conn) {
	gate.mu.Lock()
	delete(gate.connections, connection)
	gate.mu.Unlock()
}

func (gate *Gate) closeAll() {
	gate.mu.Lock()
	connections := make([]net.Conn, 0, len(gate.connections))
	for connection := range gate.connections {
		connections = append(connections, connection)
	}
	gate.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func networkFor(address string) string {
	host, _, _ := net.SplitHostPort(address)
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "tcp6"
	}
	return "tcp4"
}
