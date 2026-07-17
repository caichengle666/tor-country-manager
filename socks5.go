package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func dialViaSOCKS5(ctx context.Context, proxyAddress, targetAddress string) (net.Conn, error) {
	return dialSOCKS5(ctx, proxyAddress, targetAddress, "", "", 10*time.Second)
}

func dialViaUpstreamSOCKS5(ctx context.Context, proxyAddress, targetAddress, username, password string) (net.Conn, error) {
	return dialSOCKS5(ctx, proxyAddress, targetAddress, username, password, 12*time.Second)
}

func dialSOCKS5(ctx context.Context, proxyAddress, targetAddress, username, password string, timeout time.Duration) (net.Conn, error) {
	if (username == "") != (password == "") {
		return nil, errors.New("SOCKS5 username and password must be provided together")
	}
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) { _ = connection.Close(); return nil, err }
	methods := []byte{0}
	if username != "" {
		methods = append(methods, 2)
	}
	if _, err := connection.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return fail(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil || response[0] != 5 {
		if err == nil {
			err = errors.New("invalid SOCKS5 authentication response")
		}
		return fail(err)
	}
	switch response[1] {
	case 0:
	case 2:
		if username == "" || len(username) > 255 || len(password) > 255 {
			return fail(errors.New("SOCKS5 credentials are missing or too long"))
		}
		auth := append([]byte{1, byte(len(username))}, username...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, password...)
		if _, err := connection.Write(auth); err != nil {
			return fail(err)
		}
		if _, err := io.ReadFull(connection, response); err != nil || response[0] != 1 || response[1] != 0 {
			if err == nil {
				err = errors.New("SOCKS5 credentials were rejected")
			}
			return fail(err)
		}
	default:
		return fail(errors.New("SOCKS5 authentication negotiation failed"))
	}
	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		return fail(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || len(host) > 255 {
		return fail(errors.New("invalid SOCKS5 target"))
	}
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := connection.Write(request); err != nil {
		return fail(err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil || header[0] != 5 || header[1] != 0 {
		if err == nil {
			err = fmt.Errorf("SOCKS5 proxy returned status %d", header[1])
		}
		return fail(err)
	}
	addressLength := 0
	switch header[3] {
	case 1:
		addressLength = 4
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(connection, length); err != nil {
			return fail(err)
		}
		addressLength = int(length[0])
	case 4:
		addressLength = 16
	default:
		return fail(errors.New("SOCKS5 proxy returned an unknown address type"))
	}
	if _, err := io.CopyN(io.Discard, connection, int64(addressLength+2)); err != nil {
		return fail(err)
	}
	return connection, nil
}
