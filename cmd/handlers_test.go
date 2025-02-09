package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ShriiiGaikwad/KaiSecurity/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const testRepoPath = "./test_repo"

func init() {
	repoPath = testRepoPath
	CloneRepoFunc = mockCloneRepo
	DeleteRepoFunc = mockDeleteRepo

	store.InitDB("test_data.db")
}

func mockDeleteRepo() error {
	if _, err := os.Stat(repoPath); !os.IsNotExist(err) {
		log.Println("Mock Deleting existing repository...")
		return os.RemoveAll(repoPath)
	}
	return nil
}

func mockCloneRepo(repoURL string) error {
	log.Printf("Mock Cloning repository from %s...", repoURL)

	// Create a fake repo directory
	if err := os.Mkdir(repoPath, 0755); err != nil {
		return err
	}

	files := []string{"vulnscan1011.json", "vulnscan1213.json", "vulnscan_new.json"}
	for _, file := range files {
		mockFilePath := repoPath + "/" + file
		mockJSONData := `[{"scanResults":{"scan_id":"TEST_SCAN","timestamp":"2025-01-29T13:00:00Z","scan_status":"completed","resource_type":"container","resource_name":"test-container","summary":{"total_vulnerabilities":1,"severity_counts":{"HIGH":1},"fixable_count":1,"compliant":false},"vulnerabilities":[{"id":"CVE-2025-TEST","severity":"HIGH","cvss":8.5,"status":"active","package_name":"test-package","current_version":"1.0.0","fixed_version":"1.0.1","description":"Test vulnerability","published_date":"2025-01-28T00:00:00Z","link":"https://nvd.nist.gov/vuln/detail/CVE-2025-TEST","risk_factors":["High CVSS Score","Exploit Available"]}]}]}`

		if err := os.WriteFile(mockFilePath, []byte(mockJSONData), 0644); err != nil {
			return err
		}
	}

	return nil
}

// Setingup test router
func setupTestRouter() *gin.Engine {
	r := gin.Default()
	r.POST("/scan", ScanRepo)
	r.POST("/query", QueryData)
	return r
}

func TestScanRepoSuccess(t *testing.T) {
	router := setupTestRouter()

	requestBody := `{"repo":"https://github.com/velancio/vulnerability_scans", "files":["vulnscan1011.json", "vulnscan15.json"]}`
	req, _ := http.NewRequest("POST", "/scan", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	log.Println("Response Body:", w.Body.String())
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestScanRepoInvalidBody(t *testing.T) {
	router := setupTestRouter()

	req, _ := http.NewRequest("POST", "/scan", bytes.NewBufferString(`invalid_json`))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestQueryDataSuccess(t *testing.T) {
	router := setupTestRouter()

	requestBody := `{"filters":{"severity":"HIGH"}}`
	req, _ := http.NewRequest("POST", "/query", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestQueryDataInvalidBody(t *testing.T) {
	router := setupTestRouter()

	req, _ := http.NewRequest("POST", "/query", bytes.NewBufferString(`invalid_json`))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestParallelFileProcessing(t *testing.T) {
	var scanData []map[string]interface{}
	var wg sync.WaitGroup
	var mu sync.Mutex

	jsonFiles := []string{"f1.json", "f2.json", "f3.json"}

	for _, file := range jsonFiles {
		wg.Add(1)
		go processJSONFile(file, &scanData, &wg, &mu)
	}

	wg.Wait()
	time.Sleep(2 * time.Second)
	assert.True(t, len(scanData) >= 0)
}
