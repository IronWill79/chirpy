package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/IronWill79/chirpy/internal/chirp"
	"github.com/IronWill79/chirpy/internal/validation"
	_ "github.com/lib/pq"
)

var metricsTemplate = `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, req)
	})
}

func (cfg *apiConfig) handleDisplayMetrics(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(metricsTemplate, cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) handleResetMetrics(w http.ResponseWriter, req *http.Request) {
	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Metrics reset"))
}

func readinessHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func respondWithError(w http.ResponseWriter, code int, msg string) error {
	return respondWithJSON(w, code, map[string]string{"error": msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) error {
	response, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
	return nil
}

func validationHandler(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	c := chirp.Chirp{}
	err := decoder.Decode(&c)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		err = respondWithError(w, 500, "Something went wrong")
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
		}
		return
	}
	if len(c.Body) > 140 {
		log.Printf("Chirp is too long: %s", c.Body)
		err = respondWithError(w, 400, "Chirp is too long")
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
		}
		return
	}
	cleanedBody := chirp.CleanChirp(c.Body)
	respBody := validation.ChirpValidationSuccess{
		CleanedBody: cleanedBody,
	}
	err = respondWithJSON(w, 200, respBody)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
	}
}

func main() {
	apiCfg := apiConfig{}
	mux := http.NewServeMux()
	mux.Handle("/app/",
		apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))),
	)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handleDisplayMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.handleResetMetrics)
	mux.HandleFunc("GET /api/healthz", readinessHandler)
	mux.HandleFunc("POST /api/validate_chirp", validationHandler)
	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	err := server.ListenAndServe()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
