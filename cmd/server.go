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
		cfg.UpdateHostname(target)
	}
	port := r.Form.Get("port")
	if port != "" {
		intPort, err := strconv.Atoi(port)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cfg.UpdatePort(intPort)
	}
	configure()
}

func runServer() {
	http.HandleFunc("/reconfigure", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))

}
