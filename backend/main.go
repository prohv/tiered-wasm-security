package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"sync/atomic"
)

type Response struct {
	Status     string `json:"status"`
	Method     string `json:"method"`
	BytesRead  int64  `json:"bytes_read"`
	RequestID  string `json:"request_id,omitempty"`
	TotalCount uint64 `json:"total_count"`
}

var requestCounter uint64

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	count := atomic.AddUint64(&requestCounter, 1)

	// Read body to measure received bytes
	var bytesRead int64
	if r.Body != nil {
		defer r.Body.Close()
		n, err := io.Copy(io.Discard, r.Body)
		if err == nil {
			bytesRead = n
		}
	}

	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = r.Header.Get("x-request-id")
	}

	resp := Response{
		Status:     "ok",
		Method:     r.Method,
		BytesRead:  bytesRead,
		RequestID:  reqID,
		TotalCount: count,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Backend-Handled", "true")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/test", testHandler)

	log.Printf("Starting backend HTTP service on :%s ...", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
