package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ShriiiGaikwad/KaiSecurity/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var (
	CloneRepoFunc  = CloneRepo
	DeleteRepoFunc = DeleteRepo
)

var repoPath = "./cloned_repo"

func DeleteRepo() error {
	if _, err := os.Stat(repoPath); !os.IsNotExist(err) {
		//log.Println("Deleting existing repository and cleaning up old files...")
		err := os.RemoveAll(repoPath) // Remove the entire folder
		if err != nil {
			log.Printf("ERROR: Failed to delete %s: %v", repoPath, err)
			return err
		}
	}

	err := os.MkdirAll(repoPath, 0755)
	if err != nil {
		log.Printf("ERROR: Failed to recreate %s: %v", repoPath, err)
		return err
	}

	log.Println("Successfully cleaned repository directory.")
	return nil
}

const maxRetries = 2
const maxConcurrentFiles = 3

var concurrentFiles int32
var sem = make(chan struct{}, maxConcurrentFiles)

func CloneRepo(repoURL string) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		log.Printf("Attempt %d: Cloning repository from %s...", i+1, repoURL)
		cmd := exec.Command("git", "clone", repoURL, repoPath)
		err = cmd.Run()
		if err == nil {
			return nil
		}
		log.Printf("Clone attempt %d failed: %v", i+1, err)
		time.Sleep(5 * time.Second)
	}
	return err
}

func AllJSONFiles(dir string) ([]string, error) {
	var jsonFiles []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			jsonFiles = append(jsonFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return jsonFiles, nil
}

func processJSONFile(filePath string, scanData *[]map[string]interface{}, wg *sync.WaitGroup, mu *sync.Mutex) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()
	atomic.AddInt32(&concurrentFiles, 1)
	//log.Printf("Currently processing %d files concurrently", atomic.LoadInt32(&concurrentFiles))

	fileStart := time.Now()
	dat, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read file %s: %v", filePath, err)
		return
	}

	var parsedData []map[string]interface{}
	if err := json.Unmarshal(dat, &parsedData); err != nil {
		log.Printf("Failed to parse JSON in file %s: %v", filePath, err)
		return
	}

	mu.Lock()
	*scanData = append(*scanData, parsedData...)
	mu.Unlock()

	log.Printf("Processed file %s in %v", filePath, time.Since(fileStart))
}

func ScanRepo(c *gin.Context) {
	sessionID := uuid.New().String()

	var input struct {
		Repo  string   `json:"repo"`
		Files []string `json:"files"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	if err := store.DeleteAllScans(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clean up existing scan data"})
		return
	}

	if err := DeleteRepoFunc(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete old repository"})
		return
	}

	if err := CloneRepoFunc(input.Repo); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clone repository"})
		return
	}

	allFiles, err := AllJSONFiles(repoPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan JSON files"})
		return
	}

	filesToScan := []string{}
	if len(input.Files) > 0 {
		fileSet := make(map[string]bool)
		for _, file := range allFiles {
			fileSet[filepath.Base(file)] = true
		}
		for _, file := range input.Files {
			if fileSet[file] {
				filesToScan = append(filesToScan, filepath.Join(repoPath, file))
			}
		}
	} else {
		filesToScan = allFiles // if no input files are given
	}

	if len(filesToScan) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No valid files to scan"})
		return
	}

	var scanData []map[string]interface{}
	var wg sync.WaitGroup
	var mu sync.Mutex

	start := time.Now()

	for _, filePath := range filesToScan {
		wg.Add(1)
		go processJSONFile(filePath, &scanData, &wg, &mu)
	}

	wg.Wait()
	duration := time.Since(start)
	log.Printf("Total scan time: %v", duration)

	store.SaveScanData(scanData, sessionID, filesToScan)

	c.JSON(http.StatusOK, gin.H{"status": "Scan completed"})
}

func QueryData(c *gin.Context) {
	var input struct {
		Filters map[string]string `json:"filters"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		log.Printf("Invalid JSON payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON payload"})
		return
	}

	severity := input.Filters["severity"]
	log.Printf("Received query for severity: %s", severity)

	results, err := store.QueryDB("severity", severity)
	if err != nil {
		log.Printf("Error querying database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying database"})
		return
	}

	c.JSON(http.StatusOK, results)
}
