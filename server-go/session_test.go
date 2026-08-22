package main

import (
	"errors"
	"testing"
	"time"
)

func TestSessionLocksAfterSecondParticipant(t *testing.T) {
	manager := NewSessionManager()
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
	manager := NewSessionManager()
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
	manager := NewSessionManager()
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

func TestSessionHasImmutableTenMinuteExpiryAndEnablesDirectFileRelay(t *testing.T) {
	manager := NewSessionManager()
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
	if !status.FileTransferAvailable {
		t.Fatal("direct encrypted file relay must be enabled without object storage")
	}
}

func TestExpiryDestructionInvalidatesStatusAndFutureJoins(t *testing.T) {
	manager := NewSessionManager()
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

func TestIdleSessionRemainsAvailableUntilAnExplicitLifecycleCondition(t *testing.T) {
	manager := NewSessionManager()
	id, creatorToken, err := manager.Create()
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := manager.Status(id, creatorToken); err != nil {
		t.Fatalf("an idle session must remain available before its absolute deadline, got %v", err)
	}
}
