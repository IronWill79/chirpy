package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/IronWill79/chirpy/internal/auth"
	"github.com/IronWill79/chirpy/internal/chirp"
	"github.com/IronWill79/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var metricsTemplate = `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`

type apiConfig struct {
	dbQueries      *database.Queries
	fileserverHits atomic.Int32
}

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
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
	cfg.dbQueries.DeleteUsers(req.Context())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Metrics and users reset"))
}

func (cfg *apiConfig) handleCreateUser(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	u := User{}
	err := decoder.Decode(&u)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		err = respondWithError(w, 500, "Something went wrong")
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
		}
		return
	}
	hashedPassword, err := auth.HashPassword(u.Password)
	if err != nil {
		log.Printf("Error hashing password: %s", err)
		err = respondWithError(w, 500, "Something went wrong")
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
		}
		return
	}
	user, err := cfg.dbQueries.CreateUser(req.Context(), database.CreateUserParams{
		Email:          u.Email,
		HashedPassword: hashedPassword,
	})
	if err != nil {
		log.Printf("Error creating user: %s", err)
		err = respondWithError(w, 500, "Something went wrong")
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
		}
		return
	}
	respBody := UserResponse{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	}
	err = respondWithJSON(w, 201, respBody)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
	}
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

func (cfg *apiConfig) handleListChirps(w http.ResponseWriter, req *http.Request) {
	chirps, err := cfg.dbQueries.ListChirps(req.Context())
	if err != nil {
		log.Printf("Error getting chirps: %s", err)
		err = respondWithError(w, 500, "Something went wrong")
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
		}
		return
	}
	respBody := []chirp.Chirp{}
	for _, c := range chirps {
		respBody = append(respBody, chirp.Chirp{
			ID:        c.ID,
			CreatedAt: c.CreatedAt,
			UpdatedAt: c.UpdatedAt,
			Body:      c.Body,
			UserID:    c.UserID,
		})
	}
	err = respondWithJSON(w, 200, respBody)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
	}
}

func (cfg *apiConfig) handleCreateChirp(w http.ResponseWriter, req *http.Request) {
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
	ch, err := cfg.dbQueries.CreateChirp(req.Context(), database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: c.UserID,
	})
	if err != nil {
		log.Printf("Error creating chirp: %s", err)
		err = respondWithError(w, 500, "Something went wrong")
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
		}
		return
	}
	err = respondWithJSON(w, 201, chirp.ChirpResponse{
		ID:        ch.ID,
		CreatedAt: ch.CreatedAt,
		UpdatedAt: ch.UpdatedAt,
		Body:      ch.Body,
		UserID:    ch.UserID,
	})
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
	}
}

func (cfg *apiConfig) handleGetChirpById(w http.ResponseWriter, req *http.Request) {
	id_string := req.PathValue("chirp_id")
	id, err := uuid.Parse(id_string)
	if err != nil {
		log.Printf("Error parsing UUID: %s", err)
		err = respondWithError(w, 500, "Something went wrong")
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
		}
		return
	}
	c, err := cfg.dbQueries.GetChirpById(req.Context(), id)
	if err != nil {
		log.Printf("Error retrieving chirp: %s", err)
		err = respondWithError(w, 404, "Something went wrong")
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
		}
		return
	}
	err = respondWithJSON(w, 200, chirp.Chirp{
		ID:        c.ID,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
		Body:      c.Body,
		UserID:    c.UserID,
	})
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
	}
}

func (cfg *apiConfig) handleUserLogin(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	u := User{}
	err := decoder.Decode(&u)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		err = respondWithError(w, 500, "Something went wrong")
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
		}
		return
	}
	user, err := cfg.dbQueries.GetUserByEmail(req.Context(), u.Email)
	if err != nil {
		log.Printf("Error retrieving user: %s", err)
		err = respondWithError(w, 401, "Incorrect email or password")
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
		}
		return
	}
	ok, err := auth.CheckPasswordHash(u.Password, user.HashedPassword)
	if err != nil || !ok {
		log.Printf("Error checking password against hash: %s", err)
		err = respondWithError(w, 401, "Incorrect email or password")
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
		}
		return
	}
	err = respondWithJSON(w, 200, UserResponse{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	})
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
	}
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("Error connecting to database: %v\n", err)
	}
	dbQueries := database.New(db)
	apiCfg := apiConfig{dbQueries: dbQueries}
	mux := http.NewServeMux()
	mux.Handle("/app/",
		apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))),
	)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handleDisplayMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.handleResetMetrics)
	mux.HandleFunc("GET /api/healthz", readinessHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.handleListChirps)
	mux.HandleFunc("GET /api/chirps/{chirp_id}", apiCfg.handleGetChirpById)
	mux.HandleFunc("POST /api/chirps", apiCfg.handleCreateChirp)
	mux.HandleFunc("POST /api/login", apiCfg.handleUserLogin)
	mux.HandleFunc("POST /api/users", apiCfg.handleCreateUser)
	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	err = server.ListenAndServe()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
