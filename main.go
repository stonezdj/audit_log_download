package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"
)

type AuditLog struct {
	ID           int       `json:"id"`
	Operation    string    `json:"operation"`
	Username     string    `json:"username"`
	Resource     string    `json:"resource"`
	ResourceType string    `json:"resource_type"`
	OpTime       time.Time `json:"op_time"`
}

func writeToCSV(auditLogs []AuditLog) error {
	file, err := os.Create("audit_logs.csv")
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header row
	headers := []string{"ID", "Operation", "Username", "Resource", "Resource Type", "Operation Time"}
	err = writer.Write(headers)
	if err != nil {
		return err
	}

	// Write data rows
	for _, log := range auditLogs {
		row := []string{
			strconv.Itoa(log.ID),
			log.Operation,
			log.Username,
			log.Resource,
			log.ResourceType,
			log.OpTime.Format(time.RFC3339),
		}
		err = writer.Write(row)
		if err != nil {
			return err
		}
	}

	return nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func main() {
	hostname := flag.String("hostname", "10.202.250.197", "Hostname or IP of Harbor instance")
	username := flag.String("username", "admin", "Username of Harbor instance")
	password := flag.String("password", "Harbor12345", "Password of Harbor instance")
	q := flag.String("q", "", "Query string to filter audit logs, such as: operation=delete,resource=~nginx,username=admin")

	flag.Parse()

	if hostname == nil {
		fmt.Println("Hostname is required")
		return
	}

	if username == nil {
		fmt.Println("Username is required")
		return
	}
	if password == nil {
		fmt.Println("Password is required")
		return
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	baseUrl := fmt.Sprintf("https://%s/api/v2.0/audit-logs", *hostname)
	method := "GET"

	client := &http.Client{}
	var auditLogs []AuditLog

	page := 1
	pageSize := 15
	totalPages := 1
	for page <= totalPages {
		// Build URL with page parameter
		// Append q parameter to add more conditions, such as: q=operation=delete,resource=~nginx
		url := fmt.Sprintf("%s?page_size=%d&page=%d", baseUrl, pageSize, page)
		if q != nil && len(*q) > 0 {
			url = fmt.Sprintf("%s&q=%s", url, *q)
			//fmt.Println(url)
		}

		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			fmt.Println(err)
			return
		}
		req.Header.Add("Authorization", fmt.Sprintf("Basic %s", basicAuth(*username, *password)))

		res, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			fmt.Println(err)
			return
		}

		// Get total number of pages from response header
		var totalCount int
		if totalPages == 1 {
			totalCountStr := res.Header.Get("X-Total-Count")
			if len(totalCountStr) == 0 {
				totalCount = 0
			} else {
				totalCount, err = strconv.Atoi(totalCountStr)
				if err != nil {
					fmt.Println(err)
					return
				}
			}
			totalPages = int(math.Ceil(float64(totalCount) / float64(pageSize)))
		}

		// Decode JSON response into auditLogs slice
		var logs []AuditLog
		err = json.Unmarshal(body, &logs)
		if err != nil {
			fmt.Println(err)
			return
		}
		auditLogs = append(auditLogs, logs...)

		page++
	}

	// Write auditLogs to CSV
	err := writeToCSV(auditLogs)
	if err != nil {
		fmt.Println(err)
		return
	}
}
