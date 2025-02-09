# KaiSecurity - Vulnerability Scanner

KaiSecurity is a simple web-based application designed to scan GitHub repositories for vulnerabilities and store the results in a database. It provides a RESTful API for scanning and querying vulnerabilities.

## Features
- Clone and scan GitHub repositories for JSON-based vulnerability data.
- Process and store scan results in an SQLite database.
- Provide an API for querying vulnerabilities based on severity.
- Web-based interface for interacting with the API.

## Project Structure
```
├── main.go          # Entry point for the application
├── handler.go       # Handles API requests
├── handlers_test.go # Unit tests for handler functions
├── storage.go       # Database operations
├── storage_test.go  # Unit tests for database operations
├── Dockerfile       # Docker container setup
├── go.mod           # Go module dependencies
├── air.toml         # Live reload configuration
├── web/
│   ├── index.html   # Frontend UI
│   ├── app.js       # JavaScript logic for API interactionsgit
│   ├── style.css    # Styling for the UI
```

## Installation
### Prerequisites
- Go (1.23+)
- Docker
- Git

### Setup
1. Clone the repository:
   ```sh
   git clone https://github.com/ShriiiGaikwad/Kai_Security.git
   cd Kai_Security
   ```

2. Install dependencies:
   ```sh
   go mod tidy
   ```

3. Install Air for live reloading:
   ```sh
   go install github.com/air-verse/air@latest
   ```

4. Set up the environment variables by creating a `.env` file in the root directory:
   ```sh
   touch .env
   ```
   Add the following content:
   ```sh
   DATABASE_PATH=./data.db
   PORT=8080
   ```

5. Modify `air.toml` for live reloading:
   ```toml
   root = "."
   tmp_dir = "./bin"
   cmd = "go build -o ./bin/main ./cmd"
   exclude_dir = ["assets", "bin", "vendor", "testdata", "REAMD.md", "web"]
   ```

6. Run the application:
   ```sh
   go run main.go
   ```

## Docker Setup
To run the application in a Docker container, follow these steps:

1. Build the Docker image:
   ```sh
   docker build -t kai-security .
   ```

2. Run the container:
   ```sh
   docker run -p 8080:8080 --env-file .env kai-security
   ```
   This ensures that the `.env` file is copied into the Docker container and used for environment variables.

## API Endpoints
### 1. Scan Repository
- **Endpoint:** `POST /scan`
- **Request Body:**
  ```json
  {
    "repo": "https://github.com/velancio/vulnerability_scans",
    "files": ["vulnscan1011.json","vulnscan1213.json",..]
  }
  ```
- **Response:**
  ```json
  {
    "status": "Scan completed",
  }
  ```

### 2. Query Vulnerabilities
- **Endpoint:** `POST /query`
- **Request Body:**
  ```json
  {
  "filters": {
    "severity": "HIGH"
   }
  }
  ```
- **Response:**
  ```json
  [
    {
        "current_version": "1.0.0",
        "cvss": 8.5,
        "description": "Buffer overflow vulnerability in OpenSSL",
        "fixed_version": "1.0.1",
        "id": "CVE-2025-TEST",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2025-TEST",
        "package_name": "openssl",
        "published_date": "2025-01-28T00:00:00Z",
        "risk_factors": "[High CVSS Score, Public Exploit Available, Remote Code Execution]",
        "severity": "HIGH",
        "status": "completed"
    },
  ]
  ```
## Testing Instructions
### Automated Testing
The project includes unit tests using Go’s built-in testing framework. To run the tests, execute:
```sh
go test ./...
```
This will run all available tests and validate the application logic.

### Manual Testing
To manually test the API endpoints:
1. Start the application:
   ```sh
   go run main.go
   ```
2. Use a tool like `curl` or Postman to send requests:
   - Test scanning:
     ```sh
     curl -X POST http://localhost:8080/scan -H "Content-Type: application/json" -d '{"repo": "https://github.com/velancio/vulnerability_scans", "files": ["vulnscan1011.json", "vulnscan1213.json"] }'
     ```
   - Test querying vulnerabilities:
     ```sh
     curl -X POST http://localhost:8080/query -H "Content-Type: application/json" -d '{"filters": {"severity": "HIGH"}}'
     ```
3. Verify responses to ensure expected behavior.


## Running Tests
To run unit tests for handlers and storage:
```sh
go test ./...
```
###