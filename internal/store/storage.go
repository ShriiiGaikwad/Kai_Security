package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var lock sync.Mutex

func Lock() {
	lock.Lock()
}
func Unlock() {
	lock.Unlock()
}

func GetDB() *sql.DB {
	return db
}

func InitDB(dbPath string) {
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	fmt.Println(db, " ", err)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	createTables()
}

func createTables() {
	scanTable := `
	CREATE TABLE IF NOT EXISTS scans (
		scan_id TEXT PRIMARY KEY,
		timestamp TEXT,
		scan_status TEXT,
		resource_type TEXT,
		resource_name TEXT,
		total_vulnerabilities INTEGER,
		severity_counts TEXT,
		fixable_count INTEGER,
		compliant BOOLEAN
	);`

	vulnTable := `
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		scan_id TEXT,
		severity TEXT,
		cvss REAL,
		status TEXT,
		package_name TEXT,
		current_version TEXT,
		fixed_version TEXT,
		description TEXT,
		published_date TEXT,
		link TEXT,
		FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
	);`

	riskFactorTable := `
	CREATE TABLE IF NOT EXISTS risk_factors (
		vuln_id TEXT,
		risk_factor TEXT,
		PRIMARY KEY (vuln_id, risk_factor),
		FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
	);`

	_, err := db.Exec(scanTable)
	if err != nil {
		log.Fatalf("Failed to create scans table: %v", err)
	}

	_, err = db.Exec(vulnTable)
	if err != nil {
		log.Fatalf("Failed to create vulnerabilities table: %v", err)
	}

	_, err = db.Exec(riskFactorTable)
	if err != nil {
		log.Fatalf("Failed to create risk_factors table: %v", err)
	}
}

func DeleteAllScans() error {
	fmt.Println("in delete")
	lock.Lock()
	defer lock.Unlock()

	queries := []string{
		//just deleting the roes/data
		`DELETE FROM risk_factors;`,
		`DELETE FROM vulnerabilities;`,
		`DELETE FROM scans;`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			log.Printf("Error deleting data with query: %s. Error: %v", query, err)
			return err
		}
	}

	//log.Println("All previous scan data deleted.")
	return nil
}

func SaveScanData(scanData []map[string]interface{}, sessionID string, files []string) {
	lock.Lock()
	defer lock.Unlock()

	for _, scan := range scanData {

		scanResults := scan["scanResults"].(map[string]interface{})
		var scanID string
		if id, exists := scanResults["scan_id"]; exists {
			if idStr, ok := id.(string); ok {
				scanID = idStr
			} else {
				log.Printf("scan_id exists but is not a string: %v", id)
			}
		} else if id, exists := scanResults["scanId"]; exists {
			if idStr, ok := id.(string); ok {
				scanID = idStr
			} else {
				log.Printf("scanId exists but is not a string: %v", id)
			}
		}
		fmt.Println(scanID)
		var timestamp string
		if ts, exists := scanResults["timestamp"]; exists {
			if tsStr, ok := ts.(string); ok {
				timestamp = tsStr
			} else {
				log.Printf("timestamp exists but is not a string: %v", ts)
			}
		} else if ts, exists := scanResults["scanTime"]; exists {
			if tsStr, ok := ts.(string); ok {
				timestamp = tsStr
			} else {
				log.Printf("scanTime exists but is not a string: %v", ts)
			}
		}

		var status string
		if st, exists := scanResults["scan_status"]; exists {
			if stStr, ok := st.(string); ok {
				status = stStr
			} else {
				log.Printf("scan_status exists but is not a string: %v", st)
			}
		} else if st, exists := scanResults["status"]; exists {
			if stStr, ok := st.(string); ok {
				status = stStr
			} else {
				log.Printf("status exists but is not a string: %v", st)
			}
		}

		var resourceType string
		if rt, exists := scanResults["resource_type"]; exists {
			resourceType, _ = rt.(string)
		} else if details, exists := scanResults["resourceDetails"].(map[string]interface{}); exists {
			if rt, ok := details["type"].(string); ok {
				resourceType = rt
			}
		}

		var resourceName string
		if rn, exists := scanResults["resource_name"]; exists {
			resourceName, _ = rn.(string)
		} else if details, exists := scanResults["resourceDetails"].(map[string]interface{}); exists {
			if rn, ok := details["name"].(string); ok {
				resourceName = rn
			}
		}
		var totalVulns, fixableCount int
		var severityCounts string
		var compliant bool

		if summary, exists := scanResults["summary"].(map[string]interface{}); exists {
			if v, ok := summary["total_vulnerabilities"].(float64); ok {
				totalVulns = int(v)
			} else if v, ok := summary["totalIssues"].(float64); ok {
				totalVulns = int(v)
			} else {
				totalVulns = 0
			}

			if v, ok := summary["fixable_count"].(float64); ok {
				fixableCount = int(v)
			} else if v, ok := summary["fixableIssues"].(float64); ok {
				fixableCount = int(v)
			} else {
				fixableCount = 0
			}

			if counts, ok := summary["severity_counts"]; ok {
				if jsonCounts, err := json.Marshal(counts); err == nil {
					severityCounts = string(jsonCounts)
				}
			} else if counts, ok := summary["severityBreakdown"]; ok {
				if jsonCounts, err := json.Marshal(counts); err == nil {
					severityCounts = string(jsonCounts)
				}
			}

			if comp, ok := summary["compliant"].(bool); ok {
				compliant = comp
			} else {
				compliant = false //deafult
			}
		}

		var exists int
		err := db.QueryRow("SELECT COUNT(*) FROM scans WHERE scan_id = ?", scanID).Scan(&exists)
		if err != nil {
			log.Printf("Error checking scan_id existence: %v", err)
			continue
		}

		if exists > 0 {
			log.Printf("Scan ID %s already exists. Skipping insert.", scanID)
			continue
		}

		_, err = db.Exec(`
            INSERT INTO scans (scan_id, timestamp, scan_status, resource_type, resource_name, total_vulnerabilities, severity_counts, fixable_count, compliant)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			scanID, timestamp, status, resourceType, resourceName, totalVulns, string(severityCounts), fixableCount, compliant)
		if err != nil {
			log.Printf("Failed to insert scan data: %v", err)
			continue
		}

		var vulnerabilities []interface{}
		if v, exists := scanResults["vulnerabilities"]; exists {
			vulnerabilities, _ = v.([]interface{})
		} else if v, exists := scanResults["findings"]; exists {
			vulnerabilities, _ = v.([]interface{})
		}

		for _, v := range vulnerabilities {
			vuln, ok := v.(map[string]interface{})
			if !ok {
				log.Println("Invalid vulnerability format; skipping")
				continue
			}

			var vulnID, severity, packageName, currentVersion, fixedVersion, description, publishedDate, link string
			var cvss float64

			if id, exists := vuln["id"]; exists {
				vulnID, _ = id.(string)
			} else if id, exists := vuln["cveId"]; exists {
				vulnID, _ = id.(string)
			}

			if sev, exists := vuln["severity"]; exists {
				severity, _ = sev.(string)
			}

			if score, exists := vuln["cvss"]; exists {
				if cvssVal, ok := score.(float64); ok {
					cvss = cvssVal
				}
			} else if score, exists := vuln["score"]; exists {
				if cvssVal, ok := score.(float64); ok {
					cvss = cvssVal
				}
			}

			if pkg, exists := vuln["package_name"]; exists {
				packageName, _ = pkg.(string)
				if cv, exists := vuln["current_version"]; exists {
					currentVersion, _ = cv.(string)
				}
				if fv, exists := vuln["fixed_version"]; exists {
					fixedVersion, _ = fv.(string)
				}
			} else if pkgInfo, exists := vuln["package"]; exists {
				if pkgMap, ok := pkgInfo.(map[string]interface{}); ok {
					packageName, _ = pkgMap["name"].(string)
					currentVersion, _ = pkgMap["version"].(string)
					fixedVersion, _ = pkgMap["fixedVersion"].(string)
				}
			}

			if desc, exists := vuln["description"]; exists {
				description, _ = desc.(string)
			}

			if pubDate, exists := vuln["published_date"]; exists {
				publishedDate, _ = pubDate.(string)
			} else if pubDate, exists := vuln["firstDetected"]; exists {
				publishedDate, _ = pubDate.(string)
			}

			if ln, exists := vuln["link"]; exists {
				link, _ = ln.(string)
			}

			_, err = db.Exec(`
                INSERT INTO vulnerabilities (id, scan_id, severity, cvss, status, package_name, current_version, fixed_version, description, published_date, link)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
				vulnID, scanID, severity, cvss, status, packageName, currentVersion, fixedVersion, description, publishedDate, link,
			)
			if err != nil {
				log.Printf("Failed to insert vulnerability: %v", err)
				continue
			}

			var riskFactors []interface{}
			if rf, exists := vuln["risk_factors"]; exists {
				riskFactors, _ = rf.([]interface{})
			} else if threat, exists := vuln["threatContext"]; exists {
				if threatMap, ok := threat.(map[string]interface{}); ok {
					if inWild, ok := threatMap["inTheWild"].(bool); ok && inWild {
						riskFactors = append(riskFactors, "In The Wild")
					}
					if hasExploit, ok := threatMap["hasExploit"].(bool); ok && hasExploit {
						riskFactors = append(riskFactors, "Exploit Available")
					}
					if exploitMaturity, ok := threatMap["exploitMaturity"].(string); ok {
						riskFactors = append(riskFactors, "Exploit Maturity: "+exploitMaturity)
					}
				}
			}

			for _, factor := range riskFactors {
				if rfStr, ok := factor.(string); ok {
					_, err = db.Exec(`INSERT INTO risk_factors (vuln_id, risk_factor) VALUES (?, ?)`, vulnID, rfStr)
					if err != nil {
						log.Printf("Failed to insert risk factor: %v", err)
					}
				}
			}
		}
	}
}

func QueryDB(filterKey string, filterValue string) ([]map[string]interface{}, error) {
	lock.Lock()
	defer lock.Unlock()

	var results []map[string]interface{}

	query := ` SELECT 
    v.id AS vulnerability_id, 
    v.severity, 
    v.cvss, 
    COALESCE(v.status, ''), 
    v.package_name, 
    v.current_version, 
    v.fixed_version, 
    v.description, 
    v.published_date, 
    COALESCE(v.link, ''), 
    COALESCE('[' || GROUP_CONCAT(r.risk_factor, ', ') || ']', '') 
    FROM vulnerabilities v
    LEFT JOIN risk_factors r ON v.id = r.vuln_id
    WHERE v.` + filterKey + ` = ?
    GROUP BY v.id, v.severity, v.cvss, v.status, v.package_name, v.current_version, v.fixed_version, v.description, v.published_date, v.link`
	rows, err := db.Query(query, filterValue)
	if err != nil {
		log.Printf("Error querying database: %v", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var vulnID, severity, status, packageName, currentVersion, fixedVersion, description, publishedDate, link, riskFactors string
		var cvss float64

		err := rows.Scan(&vulnID, &severity, &cvss, &status, &packageName, &currentVersion, &fixedVersion, &description, &publishedDate, &link, &riskFactors)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}

		results = append(results, map[string]interface{}{
			"id":              vulnID,
			"severity":        severity,
			"cvss":            cvss,
			"status":          status,
			"package_name":    packageName,
			"current_version": currentVersion,
			"fixed_version":   fixedVersion,
			"description":     description,
			"published_date":  publishedDate,
			"link":            link,
			"risk_factors":    riskFactors,
		})
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}
