package store_test

import (
	"testing"

	"github.com/ShriiiGaikwad/KaiSecurity/internal/store"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

func setupTestDB(t *testing.T) {
	t.Helper()
	store.InitDB(":memory:") // Initialize tables in an in-memory database
}

func cleanupTestDB() {
	store.DeleteAllScans()
}

func TestDeleteAllScans(t *testing.T) {
	setupTestDB(t)
	defer cleanupTestDB()

	// Insert mock scan data
	_, err := store.GetDB().Exec("INSERT INTO scans (scan_id, timestamp, scan_status, resource_type, resource_name, total_vulnerabilities, severity_counts, fixable_count, compliant) VALUES ('test_scan', '2025-02-08T10:00:00Z', 'completed', 'container', 'test-container', 5, '{}', 2, true)")
	assert.NoError(t, err)

	// Ensure data exists
	var count int
	store.GetDB().QueryRow("SELECT COUNT(*) FROM scans").Scan(&count)
	assert.Equal(t, 1, count)

	// Delete all scans
	err = store.DeleteAllScans()
	assert.NoError(t, err)

	// Ensure data is deleted
	store.GetDB().QueryRow("SELECT COUNT(*) FROM scans").Scan(&count)
	assert.Equal(t, 0, count)
}

func TestSaveScanData(t *testing.T) {
	setupTestDB(t)
	defer cleanupTestDB()

	scanData := []map[string]interface{}{
		{
			"scanResults": map[string]interface{}{
				"scan_id":       "scan123",
				"timestamp":     "2025-02-08T10:00:00Z",
				"scan_status":   "completed",
				"resource_type": "container",
				"resource_name": "test-container",
				"summary": map[string]interface{}{
					"total_vulnerabilities": 10,
					"fixable_count":         5,
					"severity_counts":       map[string]int{"HIGH": 4, "MEDIUM": 3},
					"compliant":             true,
				},
			},
		},
	}

	store.SaveScanData(scanData, "session123", []string{"test.json"})

	// Verify that data was inserted
	var count int
	store.GetDB().QueryRow("SELECT COUNT(*) FROM scans").Scan(&count)
	assert.Equal(t, 1, count)
}

func TestQueryDB(t *testing.T) {
	setupTestDB(t)
	defer cleanupTestDB()

	// Insert mock vulnerability data
	_, err := store.GetDB().Exec("INSERT INTO vulnerabilities (id, scan_id, severity, cvss, package_name, current_version, fixed_version, description, published_date, link) VALUES ('vuln1', 'scan123', 'HIGH', 7.5, 'libssl', '1.1.1', '1.1.2', 'A vulnerability in libssl', '2025-01-01', 'https://example.com/vuln1')")
	assert.NoError(t, err)

	results, err := store.QueryDB("severity", "HIGH")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 1, "Expected at least one result, but got none.")

	if len(results) > 0 {
		assert.Equal(t, "HIGH", results[0]["severity"])
	}
}
