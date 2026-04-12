package swarm

// RelayServer provides transport relay when P2P is degraded or pinned.
//
// Works over any reliable stream (TCP, KCP-over-UDP) via net.Conn.
// Only verifies PASETO token validity — does NOT enforce flow rules.
// Relays don't touch or decide communication, they just forward frames.
//
// Relays register with the registrar like any other endpoint,
// so there is a central source of truth for available relays.
//
// Supports ping/pong for latency measurement by endpoints.

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// RelayServer relays frames between authenticated endpoints.
type RelayServer struct {
	controllerPubKey ed25519.PublicKey // registrar's public key

	mu       sync.RWMutex
	sessions map[string]*RelaySession // AddrKey -> session
}

// RelaySession is one authenticated endpoint connection.
type RelaySession struct {
	Addr   EndpointAddr
	conn   net.Conn
	claims *TokenClaims
	mu     sync.Mutex // serialises writes
}

// NewRelayServer creates a relay that trusts tokens signed by the given
// registrar public key.
func NewRelayServer(registrarPubKey ed25519.PublicKey) *RelayServer {
	return &RelayServer{
		controllerPubKey: registrarPubKey,
		sessions:         make(map[string]*RelaySession),
	}
}

// HandleConn runs the relay protocol on a single connection (TCP or KCP).
// Blocks until the connection closes. Safe to call concurrently.
func (r *RelayServer) HandleConn(conn net.Conn) error {
	defer conn.Close()

	session, err := r.authenticate(conn)
	if err != nil {
		r.writeControlFrame(conn, FrameAuthFail)
		return fmt.Errorf("auth: %w", err)
	}

	r.writeControlFrame(conn, FrameAuthOK)
	r.addSession(session)
	defer r.removeSession(session)

	for {
		hdr, payload, err := readFrame(conn)
		if err != nil {
			return err
		}

		switch hdr.Type {
		case FramePing:
			// Echo back as pong — enables latency measurement.
			pong := RelayFrameHeader{
				Type:       FramePong,
				PayloadLen: uint32(len(payload)),
			}
			session.mu.Lock()
			wErr := writeFrame(session.conn, pong, payload)
			session.mu.Unlock()
			if wErr != nil {
				return wErr
			}

		case FrameData:
			dst := EndpointAddr{
				Domain:   DomainID(hdr.DstDomain),
				Group:    GroupID(hdr.DstGroup),
				Endpoint: EndpointID(hdr.DstEndpoint),
			}
			target := r.getSession(dst.AddrKey())
			if target == nil {
				r.writeNoRoute(conn, hdr)
				continue
			}

			// Forward, writing the source into header so receiver knows sender.
			fwdHdr := RelayFrameHeader{
				Type:        FrameData,
				DstDomain:   uint8(session.Addr.Domain),
				DstGroup:    uint8(session.Addr.Group),
				DstEndpoint: uint16(session.Addr.Endpoint),
				PayloadLen:  uint32(len(payload)),
			}
			target.mu.Lock()
			wErr := writeFrame(target.conn, fwdHdr, payload)
			target.mu.Unlock()
			if wErr != nil {
				r.removeSession(target)
			}

		default:
			// Ignore unknown frame types.
		}
	}
}

// SessionCount returns the number of active relay sessions.
func (r *RelayServer) SessionCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// --- internal ---

func (r *RelayServer) authenticate(conn net.Conn) (*RelaySession, error) {
	hdr, payload, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("read auth frame: %w", err)
	}
	if hdr.Type != FrameAuth {
		return nil, fmt.Errorf("expected FrameAuth (0x%02x), got 0x%02x", FrameAuth, hdr.Type)
	}

	claims, err := VerifyToken(string(payload), r.controllerPubKey)
	if err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}

	addr := EndpointAddr{
		Domain:    claims.Domain,
		Group:     claims.Group,
		Endpoint:  claims.EndpointID,
		RoleFlags: claims.RoleFlags,
	}

	return &RelaySession{Addr: addr, conn: conn, claims: claims}, nil
}

func (r *RelayServer) addSession(s *RelaySession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s.Addr.AddrKey()] = s
}

func (r *RelayServer) removeSession(s *RelaySession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.sessions[s.Addr.AddrKey()]; ok && cur == s {
		delete(r.sessions, s.Addr.AddrKey())
	}
}

func (r *RelayServer) getSession(key string) *RelaySession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[key]
}

func (r *RelayServer) writeControlFrame(conn net.Conn, ft uint8) error {
	return writeFrame(conn, RelayFrameHeader{Type: ft}, nil)
}

func (r *RelayServer) writeNoRoute(conn net.Conn, orig RelayFrameHeader) error {
	return writeFrame(conn, RelayFrameHeader{
		Type:        FrameNoRoute,
		DstDomain:   orig.DstDomain,
		DstGroup:    orig.DstGroup,
		DstEndpoint: orig.DstEndpoint,
	}, nil)
}

// --- wire protocol ---

func writeFrame(w io.Writer, hdr RelayFrameHeader, payload []byte) error {
	var buf [RelayFrameHeaderSize]byte
	buf[0] = hdr.Type
	buf[1] = hdr.DstDomain
	buf[2] = hdr.DstGroup
	binary.LittleEndian.PutUint16(buf[3:5], hdr.DstEndpoint)
	binary.LittleEndian.PutUint32(buf[5:9], hdr.PayloadLen)
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

func readFrame(r io.Reader) (RelayFrameHeader, []byte, error) {
	var buf [RelayFrameHeaderSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return RelayFrameHeader{}, nil, err
	}

	hdr := RelayFrameHeader{
		Type:        buf[0],
		DstDomain:   buf[1],
		DstGroup:    buf[2],
		DstEndpoint: binary.LittleEndian.Uint16(buf[3:5]),
		PayloadLen:  binary.LittleEndian.Uint32(buf[5:9]),
	}

	if hdr.PayloadLen > MaxRelayPayload {
		return hdr, nil, errors.New("relay frame exceeds max payload")
	}

	var payload []byte
	if hdr.PayloadLen > 0 {
		payload = make([]byte, hdr.PayloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return hdr, nil, err
		}
	}
	return hdr, payload, nil
}

// --- helpers for endpoint relay clients ---

// WriteAuthFrame sends an authentication frame to a relay.
func WriteAuthFrame(w io.Writer, token string) error {
	b := []byte(token)
	return writeFrame(w, RelayFrameHeader{Type: FrameAuth, PayloadLen: uint32(len(b))}, b)
}

// WriteDataFrame sends a data frame through a relay.
func WriteDataFrame(w io.Writer, dst EndpointAddr, payload []byte) error {
	return writeFrame(w, RelayFrameHeader{
		Type:        FrameData,
		DstDomain:   uint8(dst.Domain),
		DstGroup:    uint8(dst.Group),
		DstEndpoint: uint16(dst.Endpoint),
		PayloadLen:  uint32(len(payload)),
	}, payload)
}

// WritePingFrame sends a latency probe to a relay.
func WritePingFrame(w io.Writer, nonce []byte) error {
	return writeFrame(w, RelayFrameHeader{Type: FramePing, PayloadLen: uint32(len(nonce))}, nonce)
}

// ReadRelayFrame reads a single frame from a relay connection.
func ReadRelayFrame(r io.Reader) (RelayFrameHeader, []byte, error) {
	return readFrame(r)
}
