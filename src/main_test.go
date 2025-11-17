package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigStructure(t *testing.T) {
	// Test that Config struct can be marshaled and unmarshaled properly
	config := Config{
		Network:       "testnet",
		ActiveAccount: "test-account",
		Accounts:      map[string]string{"test-account": "0x1234567890123456789012345678901234567890"},
		ConfiguredAt:  time.Now(),
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	// Unmarshal back
	var readConfig Config
	if err := json.Unmarshal(data, &readConfig); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify fields
	if readConfig.Network != config.Network {
		t.Errorf("Network mismatch: got %s, want %s", readConfig.Network, config.Network)
	}
	if readConfig.ActiveAccount != config.ActiveAccount {
		t.Errorf("ActiveAccount mismatch: got %s, want %s", readConfig.ActiveAccount, config.ActiveAccount)
	}
	if len(readConfig.Accounts) != len(config.Accounts) {
		t.Errorf("Accounts length mismatch: got %d, want %d", len(readConfig.Accounts), len(config.Accounts))
	}
}

func TestNetworkConstants(t *testing.T) {
	// Test that network constants are defined correctly
	if testnetAPI == "" {
		t.Error("testnetAPI constant should not be empty")
	}
	if mainnetAPI == "" {
		t.Error("mainnetAPI constant should not be empty")
	}
	if keyringService == "" {
		t.Error("keyringService constant should not be empty")
	}
}

func TestConfigFileOperations(t *testing.T) {
	// Test basic config file operations
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.json")

	config := Config{
		Network:       "testnet",
		ActiveAccount: "test",
		Accounts:      map[string]string{"test": "0x1234"},
		ConfiguredAt:  time.Now(),
	}

	// Write config
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	if err := os.WriteFile(configFile, data, 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Read config back
	readData, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	var readConfig Config
	if err := json.Unmarshal(readData, &readConfig); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify
	if readConfig.Network != config.Network {
		t.Errorf("Network mismatch: got %s, want %s", readConfig.Network, config.Network)
	}
	if readConfig.ActiveAccount != config.ActiveAccount {
		t.Errorf("ActiveAccount mismatch: got %s, want %s", readConfig.ActiveAccount, config.ActiveAccount)
	}
}

func TestVersionConstant(t *testing.T) {
	// Test that version is defined and not empty
	if version == "" {
		t.Error("version constant should not be empty")
	}
}

func TestStructTypes(t *testing.T) {
	// Test that key struct types are properly defined
	
	// Test Feed struct
	feed := Feed{
		ID:          "test-id",
		Name:        "test-feed",
		Description: "test description",
		IsActive:    true,
	}
	
	if feed.ID != "test-id" {
		t.Errorf("Feed ID mismatch: got %s, want test-id", feed.ID)
	}

	// Test Entry struct
	entry := Entry{
		ID:     "test-entry-id",
		FeedID: "test-feed-id",
		Title:  "test entry",
		IsFree: true,
	}
	
	if entry.ID != "test-entry-id" {
		t.Errorf("Entry ID mismatch: got %s, want test-entry-id", entry.ID)
	}

	// Test Category struct
	category := Category{
		ID:   "test-category-id",
		Name: "test category",
	}
	
	if category.ID != "test-category-id" {
		t.Errorf("Category ID mismatch: got %s, want test-category-id", category.ID)
	}
}