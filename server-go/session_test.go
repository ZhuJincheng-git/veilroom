package main

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

type memoryStore struct{ deleted []string }

func (m *memoryStore) Put(context.Context, string, io.Reader, int64) error { return nil }
func (m *memoryStore) Get(context.Context, string) (io.ReadCloser, int64, error) {
	return nil, 0, errors.New("not implemented")
}
func (m *memoryStore) Delete(_ context.Context, key string) error {
	m.deleted = append(m.deleted, key)
	return nil
}

func TestSessionLocksAfterSecondParticipant(t *testing.T) {
	manager := NewSessionManager(&memoryStore{})
	id, creatorToken, err := manager.Create()
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if len(id) < 40 || len(creatorToken) < 40 {
		t.Fatal("session identifiers must use high entropy capabilities")
	}
	if _, err := manager.Join(id); err != nil {
		t.Fatalf("first invitee should join: %v", err)
	}
	if _, err := manager.Join(id); !errors.Is(err, errSessionLocked) {
		t.Fatalf("third participant must be rejected, got %v", err)
	}
}

func TestExplicitLeaveRevokesCapabilityAndSchedulesClosing(t *testing.T) {
	manager := NewSessionManager(&memoryStore{})
	id, creatorToken, err := manager.Create()
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := manager.Join(id); err != nil {
		t.Fatalf("join session: %v", err)
	}
	if err := manager.Leave(id, creatorToken); err != nil {
		t.Fatalf("leave session: %v", err)
	}
	if _, err := manager.Status(id, creatorToken); !errors.Is(err, errUnauthorized) {
		t.Fatalf("exited participant must not regain access, got %v", err)
	}
	manager.mu.Lock()
	state := manager.sessions[id].state
	destroyAt := manager.sessions[id].destroyAt
	manager.mu.Unlock()
	if state != stateClosing || destroyAt == nil || time.Until(*destroyAt) > exitGrace+time.Second {
		t.Fatalf("leave must initiate the one-minute closing window")
	}
}

func TestCreatorLeavingBeforeInviteeStillStartsClosingWindow(t *testing.T) {
	manager := NewSessionManager(&memoryStore{})
	id, creatorToken, err := manager.Create()
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := manager.Leave(id, creatorToken); err != nil {
		t.Fatalf("leave waiting session: %v", err)
	}
	manager.mu.Lock()
	state := manager.sessions[id].state
	destroyAt := manager.sessions[id].destroyAt
	manager.mu.Unlock()
	if state != stateClosing || destroyAt == nil {
		t.Fatal("a waiting session must begin one-minute destruction after the creator exits")
	}
}

func TestSessionHasImmutableTenMinuteExpiryAndDisablesFilesWithoutDeletableStorage(t *testing.T) {
	manager := NewSessionManager(nil)
	id, creatorToken, err := manager.Create()
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	manager.mu.Lock()
	createdAt := manager.sessions[id].createdAt
	expiresAt := manager.sessions[id].expiresAt
	manager.mu.Unlock()
	if expiresAt.Sub(createdAt) != maxSessionAge {
		t.Fatalf("session maximum lifetime must be %v", maxSessionAge)
	}
	status, err := manager.Status(id, creatorToken)
	if err != nil {
		t.Fatalf("get status: %v", err)
	}
	if status.FileTransferAvailable {
		t.Fatal("file uploads must be disabled when object deletion is not configured")
	}
}

func TestExpiryDestructionInvalidatesStatusAndFutureJoins(t *testing.T) {
	manager := NewSessionManager(nil)
	id, creatorToken, err := manager.Create()
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	// The expiry timer invokes this same destruction path after the fixed ten-minute deadline.
	manager.destroy(id)
	if _, err := manager.Status(id, creatorToken); !errors.Is(err, errSessionNotFound) {
		t.Fatalf("destroyed session status must be unavailable, got %v", err)
	}
	if _, err := manager.Join(id); !errors.Is(err, errSessionNotFound) {
		t.Fatalf("destroyed session cannot accept a later join, got %v", err)
	}
}
