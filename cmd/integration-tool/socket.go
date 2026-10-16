package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

type socketTimeouts struct {
	accept, connection, client, holdConnect, hold, poll time.Duration
}

var defaultSocketTimeouts = socketTimeouts{
	accept: 15 * time.Second, connection: 5 * time.Second, client: 2 * time.Second,
	holdConnect: 3 * time.Second, hold: 10 * time.Second, poll: 50 * time.Millisecond,
}

func socketTool(args []string, stdout io.Writer, deadlines socketTimeouts) error {
	want := map[string]int{"tcp-server": 4, "tcp-client": 4, "hold-server": 3, "hold-client": 6, "udp-server": 3, "udp-client": 4}
	if len(args) == 0 || want[args[0]] == 0 || len(args) != want[args[0]] {
		return errors.New("invalid socket operation")
	}
	switch args[0] {
	case "tcp-server", "hold-server":
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{Port: parsePort(args[1])})
		if err != nil {
			return err
		}
		defer listener.Close()
		count := 1
		if args[0] == "tcp-server" {
			count, err = strconv.Atoi(args[3])
			if err != nil || count < 1 {
				return errors.New("invalid connection count")
			}
		}
		return serveTCP(listener, args[2], count, args[0] == "hold-server", deadlines)
	case "udp-server":
		server, err := net.ListenUDP("udp4", &net.UDPAddr{Port: parsePort(args[1])})
		if err != nil {
			return err
		}
		defer server.Close()
		return serveUDP(server, args[2], deadlines)
	case "tcp-client":
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort(args[1], args[2]), deadlines.client)
		if err != nil {
			return clientError(err)
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(deadlines.client)); err != nil {
			return err
		}
		if _, err := io.WriteString(conn, args[3]); err != nil {
			return clientError(err)
		}
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			return clientError(err)
		}
		response, err := readReply(conn)
		if err != nil {
			return clientError(err)
		}
		_, err = stdout.Write(response)
		return err
	case "udp-client":
		conn, err := net.DialTimeout("udp4", net.JoinHostPort(args[1], args[2]), deadlines.client)
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(deadlines.client)); err != nil {
			return err
		}
		if _, err := io.WriteString(conn, args[3]); err != nil {
			return err
		}
		buffer := make([]byte, 4096)
		n, err := conn.Read(buffer)
		if err != nil {
			return clientError(err)
		}
		_, err = stdout.Write(buffer[:n])
		return err
	case "hold-client":
		return holdClient(args[1:], deadlines)
	}
	return errors.New("unknown operation")
}

func parsePort(port string) int {
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return -1 // The listener rejects invalid ports.
	}
	return n
}

func ready(path string) error { return os.WriteFile(path, []byte("ready\n"), 0644) }

func readReply(reader io.Reader) ([]byte, error) {
	// TCP can split a reply across packets. Read until the fixture closes its
	// write side rather than assuming that a single Read returns everything.
	return io.ReadAll(io.LimitReader(reader, 4096))
}

func serveTCP(listener *net.TCPListener, readyPath string, count int, hold bool, deadlines socketTimeouts) error {
	if err := listener.SetDeadline(time.Now().Add(deadlines.accept)); err != nil {
		return err
	}
	if err := ready(readyPath); err != nil {
		return err
	}
	for range count {
		conn, err := listener.AcceptTCP()
		if err != nil {
			return err
		}
		err = replyTCP(conn, hold, deadlines)
		conn.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func replyTCP(conn *net.TCPConn, hold bool, deadlines socketTimeouts) error {
	deadline := deadlines.connection
	if hold {
		deadline = deadlines.hold
	}
	if err := conn.SetDeadline(time.Now().Add(deadline)); err != nil {
		return err
	}
	if !hold {
		data, err := readReply(conn)
		if err != nil {
			return err
		}
		_, err = conn.Write(append([]byte("reply:"), data...))
		return err
	}
	reader := bufio.NewReader(conn)
	for range 2 {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return statusError(30)
			}
			return err
		}
		if _, err := io.WriteString(conn, "reply:"+line); err != nil {
			return err
		}
	}
	return nil
}

func holdClient(args []string, deadlines socketTimeouts) error {
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(args[0], args[1]), deadlines.holdConnect)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(deadlines.hold)); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, "one\n"); err != nil {
		return err
	}
	first, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if err := os.WriteFile(args[2], []byte(first), 0644); err != nil {
		return err
	}
	deadline := time.Now().Add(deadlines.hold)
	for {
		if _, err := os.Stat(args[3]); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return err
		}
		if !time.Now().Before(deadline) {
			return statusError(31)
		}
		time.Sleep(deadlines.poll)
	}
	if _, err := io.WriteString(conn, "two\n"); err != nil {
		return err
	}
	second, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	return os.WriteFile(args[4], []byte(first+second), 0644)
}

func serveUDP(server *net.UDPConn, readyPath string, deadlines socketTimeouts) error {
	if err := server.SetDeadline(time.Now().Add(deadlines.accept)); err != nil {
		return err
	}
	if err := ready(readyPath); err != nil {
		return err
	}
	buffer := make([]byte, 4096)
	n, address, err := server.ReadFromUDP(buffer)
	if err != nil {
		return err
	}
	_, err = server.WriteToUDP(append([]byte("reply:"), buffer[:n]...), address)
	return err
}

func clientError(err error) error {
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return statusError(20)
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return statusError(21)
	}
	return statusError(22)
}
