package g02

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestMinecraftProtocolStatusAndLoginPackets(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	errors := make(chan error, 1)
	go func() {
		for connectionNumber := 0; connectionNumber < 2; connectionNumber++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				errors <- acceptErr
				return
			}
			reader := bufio.NewReader(connection)
			packetID, handshake, readErr := readPacket(reader)
			if readErr != nil || packetID != 0 {
				connection.Close()
				errors <- fmt.Errorf("read handshake: id=%d err=%v", packetID, readErr)
				return
			}
			protocol, remaining, readErr := consumeVarInt(handshake)
			if readErr != nil {
				connection.Close()
				errors <- readErr
				return
			}
			_, remaining, readErr = consumeString(remaining)
			if readErr != nil || len(remaining) < 3 {
				connection.Close()
				errors <- fmt.Errorf("invalid handshake address: %v", readErr)
				return
			}
			remaining = remaining[2:]
			nextState, remaining, readErr := consumeVarInt(remaining)
			if readErr != nil || len(remaining) != 0 {
				connection.Close()
				errors <- fmt.Errorf("invalid handshake next state: %v", readErr)
				return
			}
			if connectionNumber == 0 {
				if protocol != -1 || nextState != 1 {
					connection.Close()
					errors <- fmt.Errorf("unexpected status handshake protocol=%d next=%d", protocol, nextState)
					return
				}
				requestID, request, requestErr := readPacket(reader)
				if requestErr != nil || requestID != 0 || len(request) != 0 {
					connection.Close()
					errors <- fmt.Errorf("invalid status request id=%d err=%v", requestID, requestErr)
					return
				}
				status := `{"version":{"name":"Paper 26.2","protocol":774},"players":{"max":20,"online":0},"description":{"text":"test"}}`
				if writeErr := writePacket(connection, 0, appendString(nil, status)); writeErr != nil {
					connection.Close()
					errors <- writeErr
					return
				}
				connection.Close()
				continue
			}
			if protocol != 774 || nextState != 2 {
				connection.Close()
				errors <- fmt.Errorf("unexpected login handshake protocol=%d next=%d", protocol, nextState)
				return
			}
			loginID, login, loginErr := readPacket(reader)
			if loginErr != nil || loginID != 0 {
				connection.Close()
				errors <- fmt.Errorf("invalid login start id=%d err=%v", loginID, loginErr)
				return
			}
			name, uuid, loginErr := consumeString(login)
			if loginErr != nil || name != "GARG02Probe" || len(uuid) != 16 {
				connection.Close()
				errors <- fmt.Errorf("invalid login payload name=%q uuid=%d err=%v", name, len(uuid), loginErr)
				return
			}
			connection.Close()
			errors <- nil
			return
		}
	}()

	protocol, name, err := discoverProtocol(listener.Addr().String(), time.Second)
	if err != nil || protocol != 774 || name != "Paper 26.2" {
		t.Fatalf("unexpected status tuple protocol=%d name=%q err=%v", protocol, name, err)
	}
	connection, err := beginLogin(listener.Addr().String(), protocol, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if err := <-errors; err != nil {
		t.Fatal(err)
	}
}

func consumeVarInt(payload []byte) (int32, []byte, error) {
	reader := bytes.NewReader(payload)
	value, err := readVarInt(reader)
	if err != nil {
		return 0, nil, err
	}
	remaining, err := io.ReadAll(reader)
	return value, remaining, err
}
