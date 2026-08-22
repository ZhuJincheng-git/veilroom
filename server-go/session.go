package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

const (
	maxSessionAge = 10 * time.Minute
	exitGrace    = time.Minute
	maxRelaySize = 128 * 1024
)

var (
	errSessionNotFound = errors.New("session not found")
	errSessionLocked   = errors.New("session is locked")
	errUnauthorized    = errors.New("session capability is invalid")
	errSessionClosing  = errors.New("session is closing")
)

type sessionState string

const (
	stateWaiting   sessionState = "WAITING"
	stateLocked    sessionState = "LOCKED"
	stateClosing   sessionState = "CLOSING"
	stateDestroyed sessionState = "DESTROYED"
)

type participant struct {
	role   string
	token  string
	online bool
	left   bool
	conn   *websocket.Conn
	send   chan []byte
}

type session struct {
	id          string
	createdAt   time.Time
	expiresAt   time.Time
	destroyAt   *time.Time
	state       sessionState
	participants map[string]*participant
	expiryTimer *time.Timer
	exitTimer   *time.Timer
}

type sessionStatus struct {
	Type         string       `json:"type"`
	State        sessionState `json:"state"`
	ExpiresAt    int64        `json:"expiresAt"`
	DestroyAt    *int64       `json:"destroyAt,omitempty"`
	You          string       `json:"you"`
	PeerOnline   bool         `json:"peerOnline"`
	PeerJoined   bool         `json:"peerJoined"`
	FileTransferAvailable bool `json:"fileTransferAvailable"`
	ServerNow    int64        `json:"serverNow"`
}

type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]*session
	now      func() time.Time
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*session),
		now:      time.Now,
	}
}

func randomCapability() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("secure random source unavailable: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (m *SessionManager) Create() (string, string, error) {
	id, err := randomCapability()
	if err != nil {
		return "", "", err
	}
	token, err := randomCapability()
	if err != nil {
		return "", "", err
	}

	now := m.now()
	s := &session{
		id:        id,
		createdAt: now,
		expiresAt: now.Add(maxSessionAge),
		state:     stateWaiting,
		participants: map[string]*participant{
			token: {role: "A", token: token, send: make(chan []byte, 16)},
		},
	}
	s.expiryTimer = time.AfterFunc(maxSessionAge, func() { m.destroy(id) })

	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return id, token, nil
}

func (m *SessionManager) Join(id string) (string, error) {
	token, err := randomCapability()
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || s.state == stateDestroyed {
		return "", errSessionNotFound
	}
	if !m.now().Before(s.expiresAt) {
		go m.destroy(id)
		return "", errSessionClosing
	}
	if s.state != stateWaiting || len(s.participants) != 1 {
		return "", errSessionLocked
	}

	s.participants[token] = &participant{role: "B", token: token, send: make(chan []byte, 16)}
	s.state = stateLocked
	m.publishStatusLocked(s)
	return token, nil
}

func (m *SessionManager) Attach(id, token string, conn *websocket.Conn) (string, error) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok || s.state == stateDestroyed {
		m.mu.Unlock()
		return "", errSessionNotFound
	}
	p, ok := s.participants[token]
	if !ok || p.left {
		m.mu.Unlock()
		return "", errUnauthorized
	}
	if s.state == stateClosing || !m.now().Before(s.expiresAt) {
		m.mu.Unlock()
		return "", errSessionClosing
	}
	if p.conn != nil {
		m.mu.Unlock()
		return "", errSessionLocked
	}
	p.conn = conn
	p.online = true
	m.publishStatusLocked(s)
	m.mu.Unlock()

	go m.writePump(id, token, conn, p.send)
	return p.role, nil
}

func (m *SessionManager) writePump(id, token string, conn *websocket.Conn, outgoing <-chan []byte) {
	for payload := range outgoing {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		err := conn.Write(ctx, websocket.MessageText, payload)
		cancel()
		if err != nil {
			m.disconnect(id, token, conn)
			return
		}
	}
}

func (m *SessionManager) Relay(id, token string, payload []byte) error {
	if len(payload) == 0 || len(payload) > maxRelaySize {
		return errors.New("relay envelope exceeds protocol limit")
	}
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return errors.New("relay payload is not a valid envelope")
	}
	switch envelope.Type {
	case "key", "ciphertext", "file-offer", "file-chunk", "ping":
	default:
		return errors.New("relay envelope type is not allowed")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || s.state != stateLocked {
		return errSessionClosing
	}
	sender, ok := s.participants[token]
	if !ok || sender.left || !sender.online {
		return errUnauthorized
	}
	for candidateToken, peer := range s.participants {
		if candidateToken == token || peer.left || !peer.online {
			continue
		}
		copyPayload := append([]byte(nil), payload...)
		select {
		case peer.send <- copyPayload:
		default:
			go m.disconnect(id, candidateToken, peer.conn)
		}
	}
	return nil
}

func (m *SessionManager) Disconnect(id, token string, conn *websocket.Conn) {
	m.disconnect(id, token, conn)
}

func (m *SessionManager) disconnect(id, token string, conn *websocket.Conn) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return
	}
	p, ok := s.participants[token]
	if !ok || p.conn != conn {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	m.leave(id, token)
}

func (m *SessionManager) Leave(id, token string) error {
	m.mu.Lock()
	_, ok := m.sessions[id]
	m.mu.Unlock()
	if !ok {
		return errSessionNotFound
	}
	m.leave(id, token)
	return nil
}

func (m *SessionManager) leave(id, token string) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok || s.state == stateDestroyed {
		m.mu.Unlock()
		return
	}
	p, ok := s.participants[token]
	if !ok || p.left {
		m.mu.Unlock()
		return
	}
	p.left = true
	p.online = false
	p.conn = nil

	now := m.now()
	allLeft := len(s.participants) == 2
	for _, participant := range s.participants {
		allLeft = allLeft && participant.left
	}
	if allLeft {
		m.mu.Unlock()
		m.destroy(id)
		return
	}
	if s.state != stateClosing {
		s.state = stateClosing
		destroyAt := now.Add(exitGrace)
		s.destroyAt = &destroyAt
		s.exitTimer = time.AfterFunc(exitGrace, func() { m.destroy(id) })
	}
	m.publishStatusLocked(s)
	m.mu.Unlock()
}

func (m *SessionManager) Status(id, token string) (sessionStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || s.state == stateDestroyed {
		return sessionStatus{}, errSessionNotFound
	}
	p, ok := s.participants[token]
	if !ok || p.left {
		return sessionStatus{}, errUnauthorized
	}
	return statusFor(s, p.role, m.now()), nil
}

func statusFor(s *session, role string, now time.Time) sessionStatus {
	peerRole := "A"
	if role == "A" {
		peerRole = "B"
	}
	peerOnline := false
	peerJoined := false
	for _, participant := range s.participants {
		if participant.role == peerRole {
			peerOnline = participant.online && !participant.left
			peerJoined = true
			break
		}
	}
	var destroyAt *int64
	if s.destroyAt != nil {
		value := s.destroyAt.UnixMilli()
		destroyAt = &value
	}
	return sessionStatus{
		Type:       "session-status",
		State:      s.state,
		ExpiresAt:  s.expiresAt.UnixMilli(),
		DestroyAt:  destroyAt,
		You:        role,
		PeerOnline: peerOnline,
		PeerJoined: peerJoined,
		FileTransferAvailable: true,
		ServerNow:  now.UnixMilli(),
	}
}

func (m *SessionManager) publishStatusLocked(s *session) {
	for _, participant := range s.participants {
		if participant.left || !participant.online {
			continue
		}
		payload, err := json.Marshal(statusFor(s, participant.role, m.now()))
		if err != nil {
			continue
		}
		select {
		case participant.send <- payload:
		default:
			go m.disconnect(s.id, participant.token, participant.conn)
		}
	}
}

func (m *SessionManager) destroy(id string) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok || s.state == stateDestroyed {
		m.mu.Unlock()
		return
	}
	s.state = stateDestroyed
	if s.expiryTimer != nil {
		s.expiryTimer.Stop()
	}
	if s.exitTimer != nil {
		s.exitTimer.Stop()
	}
	connections := make([]*websocket.Conn, 0, len(s.participants))
	for _, participant := range s.participants {
		if participant.conn != nil {
			connections = append(connections, participant.conn)
		}
		participant.left = true
		participant.online = false
		participant.conn = nil
	}
	s.participants = nil
	delete(m.sessions, id)
	m.mu.Unlock()

	for _, conn := range connections {
		_ = conn.Close(websocket.StatusPolicyViolation, "session ended")
	}
}
