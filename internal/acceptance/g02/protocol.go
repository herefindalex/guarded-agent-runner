package g02

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const maxMinecraftPacket = 1 << 20

type statusResponse struct {
	Version struct {
		Name     string `json:"name"`
		Protocol int32  `json:"protocol"`
	} `json:"version"`
}

func discoverProtocol(address string, timeout time.Duration) (int32, string, error) {
	connection, err := net.DialTimeout(networkFor(address), address, timeout)
	if err != nil {
		return 0, "", err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, "", err
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0, "", err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return 0, "", err
	}
	handshake := appendVarInt(nil, -1)
	handshake = appendString(handshake, host)
	handshake = binary.BigEndian.AppendUint16(handshake, uint16(port))
	handshake = appendVarInt(handshake, 1)
	if err := writePacket(connection, 0, handshake); err != nil {
		return 0, "", err
	}
	if err := writePacket(connection, 0, nil); err != nil {
		return 0, "", err
	}
	packetID, payload, err := readPacket(bufio.NewReader(connection))
	if err != nil {
		return 0, "", err
	}
	if packetID != 0 {
		return 0, "", fmt.Errorf("unexpected Minecraft status packet ID %d", packetID)
	}
	statusJSON, remaining, err := consumeString(payload)
	if err != nil || len(remaining) != 0 {
		return 0, "", fmt.Errorf("decode Minecraft status response: %w", err)
	}
	var response statusResponse
	decoder := json.NewDecoder(bytes.NewReader([]byte(statusJSON)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		// The status document has optional fields outside the version object.
		var envelope map[string]json.RawMessage
		if unmarshalErr := json.Unmarshal([]byte(statusJSON), &envelope); unmarshalErr != nil {
			return 0, "", fmt.Errorf("decode Minecraft status JSON: %w", unmarshalErr)
		}
		if unmarshalErr := json.Unmarshal(envelope["version"], &response.Version); unmarshalErr != nil {
			return 0, "", fmt.Errorf("decode Minecraft status version: %w", unmarshalErr)
		}
	}
	if response.Version.Protocol <= 0 || response.Version.Name == "" {
		return 0, "", fmt.Errorf("Minecraft status omitted a valid protocol tuple")
	}
	return response.Version.Protocol, response.Version.Name, nil
}

func beginLogin(address string, protocol int32, timeout time.Duration) (net.Conn, error) {
	connection, err := net.DialTimeout(networkFor(address), address, timeout)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		_ = connection.Close()
		return nil, err
	}
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fail(err)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fail(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return fail(err)
	}
	handshake := appendVarInt(nil, protocol)
	handshake = appendString(handshake, host)
	handshake = binary.BigEndian.AppendUint16(handshake, uint16(port))
	handshake = appendVarInt(handshake, 2)
	if err := writePacket(connection, 0, handshake); err != nil {
		return fail(err)
	}
	loginStart := appendString(nil, "GARG02Probe")
	// The exact supported Paper tuple uses the modern Login Start UUID field.
	probeUUID := [16]byte{0x47, 0x41, 0x52, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	loginStart = append(loginStart, probeUUID[:]...)
	if err := writePacket(connection, 0, loginStart); err != nil {
		return fail(err)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return fail(err)
	}
	return connection, nil
}

func writePacket(writer io.Writer, packetID int32, payload []byte) error {
	body := appendVarInt(nil, packetID)
	body = append(body, payload...)
	frame := appendVarInt(nil, int32(len(body)))
	frame = append(frame, body...)
	_, err := writer.Write(frame)
	return err
}

func readPacket(reader *bufio.Reader) (int32, []byte, error) {
	length, err := readVarInt(reader)
	if err != nil {
		return 0, nil, err
	}
	if length < 1 || length > maxMinecraftPacket {
		return 0, nil, fmt.Errorf("invalid Minecraft packet length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	buffer := bufio.NewReader(bytes.NewReader(payload))
	packetID, err := readVarInt(buffer)
	if err != nil {
		return 0, nil, err
	}
	rest, err := io.ReadAll(buffer)
	return packetID, rest, err
}

func appendVarInt(destination []byte, value int32) []byte {
	remaining := uint32(value)
	for {
		current := byte(remaining & 0x7f)
		remaining >>= 7
		if remaining != 0 {
			current |= 0x80
		}
		destination = append(destination, current)
		if remaining == 0 {
			return destination
		}
	}
}

func readVarInt(reader io.ByteReader) (int32, error) {
	var value uint32
	for position := 0; position < 5; position++ {
		current, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		value |= uint32(current&0x7f) << (7 * position)
		if current&0x80 == 0 {
			return int32(value), nil
		}
	}
	return 0, fmt.Errorf("Minecraft VarInt exceeds five bytes")
}

func appendString(destination []byte, value string) []byte {
	destination = appendVarInt(destination, int32(len(value)))
	return append(destination, value...)
}

func consumeString(payload []byte) (string, []byte, error) {
	reader := bytes.NewReader(payload)
	length, err := readVarInt(reader)
	if err != nil {
		return "", nil, err
	}
	if length < 0 || length > maxMinecraftPacket || int64(length) > int64(reader.Len()) {
		return "", nil, fmt.Errorf("invalid Minecraft string length %d", length)
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", nil, err
	}
	remaining, err := io.ReadAll(reader)
	return string(value), remaining, err
}

func networkFor(address string) string {
	host, _, _ := net.SplitHostPort(address)
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "tcp6"
	}
	return "tcp4"
}
