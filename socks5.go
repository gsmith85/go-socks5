package socks5

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/context"
	"slices"
)

const (
	socks5Version = uint8(5)
)

// ErrServerClosed is returned by the Server's Serve, ListenAndServe,
// and ServeConn methods after a call to Shutdown.
var ErrServerClosed = fmt.Errorf("socks5: Server closed")

// Config is used to setup and configure a Server
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is nil, then "auth-less" mode is enabled.
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger *log.Logger

	// Optional function for dialing out
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Server is reponsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
	
	// Fields for graceful shutdown
	inShutdown   atomic.Bool
	mu           sync.Mutex
	listeners    []net.Listener
	activeConns  sync.Map
	listenerDone chan struct{}
}

// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {
	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	// Ensure we have a log target
	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	server := &Server{
		config:       conf,
		listenerDone: make(chan struct{}),
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	if s.inShutdown.Load() {
		return ErrServerClosed
	}
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	if s.inShutdown.Load() {
		return ErrServerClosed
	}
	
	s.mu.Lock()
	s.listeners = append(s.listeners, l)
	s.mu.Unlock()
	
	defer func() {
		s.mu.Lock()
		for i, ln := range s.listeners {
			if ln == l {
				s.listeners = slices.Delete(s.listeners, i, i+1)
			}
		}
		s.mu.Unlock()
	}()
	
	for {
		conn, err := l.Accept()
		if err != nil {
			if s.inShutdown.Load() {
				return ErrServerClosed
			}
			return err
		}
		connID := fmt.Sprintf("%p", conn)
		s.activeConns.Store(connID, conn)
		go func() {
			s.ServeConn(conn)
			s.activeConns.Delete(connID)
		}()
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) error {
	if s.inShutdown.Load() {
		conn.Close()
		return ErrServerClosed
	}
	defer conn.Close()
	bufConn := bufio.NewReader(conn)

	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		s.config.Logger.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return err
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	// Authenticate the connection
	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		err = fmt.Errorf("Failed to authenticate: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	request, err := NewRequest(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}
	request.AuthContext = authContext
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		err = fmt.Errorf("Failed to handle request: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	return nil
}

// Shutdown gracefully shuts down the server without interrupting any
// active connections. Shutdown works by first closing all open
// listeners, then waiting for all active connections to complete.
// If the provided context expires before the shutdown is complete,
// Shutdown returns the context's error, otherwise it returns any
// error returned from closing the Server's underlying Listener(s).
//
// When Shutdown is called, Serve, ListenAndServe, and ServeConn
// immediately return ErrServerClosed. Make sure the program doesn't
// exit and waits instead for Shutdown to return.
//
// Once Shutdown has been called on a server, it may not be reused;
// future calls to methods such as Serve will return ErrServerClosed.
func (s *Server) Shutdown(ctx context.Context) error {
	s.inShutdown.Store(true)
	
	// Close all listeners
	s.mu.Lock()
	var err error
	for _, l := range s.listeners {
		if cerr := l.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	s.listeners = nil
	s.mu.Unlock()
	
	// Wait for active connections to finish
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		activeConnections := 0
		s.activeConns.Range(func(_, _ any) bool {
			activeConnections++
			return true
		})
		
		if activeConnections == 0 {
			return err
		}
		
		select {
		case <-ctx.Done():
			// Force close any remaining connections
			s.activeConns.Range(func(key, value any) bool {
				if conn, ok := value.(net.Conn); ok {
					conn.Close()
				}
				s.activeConns.Delete(key)
				return true
			})
			return ctx.Err()
		case <-ticker.C:
			// Continue waiting
		}
	}
}
