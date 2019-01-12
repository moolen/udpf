package main

import (
	"log"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	target := r.Form.Get("target")
	if target != "" {
		cfg.mu.Lock()
		cfg.targetHost = target
		cfg.mu.Unlock()
	}
	port := r.Form.Get("port")
	if port != "" {
		intPort, err := strconv.Atoi(port)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cfg.mu.Lock()
		cfg.targetPort = intPort
		cfg.mu.Unlock()
	}
	compile(cfg)
}

func runServer() {
	http.HandleFunc("/recompile", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))

}
