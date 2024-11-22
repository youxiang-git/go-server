package main

import (
	"fmt"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		fmt.Errorf("HTTP server ListenAndServe: %v", err)
	}

}
