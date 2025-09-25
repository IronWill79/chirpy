package chirp

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

var profanities = []string{"kerfuffle", "sharbert", "fornax"}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type ChirpResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func CleanChirp(chirp string) string {
	words := strings.Split(chirp, " ")
	cleanedWords := []string{}
	for _, word := range words {
		found := false
		for i := range profanities {
			if profanities[i] == strings.ToLower(word) {
				cleanedWords = append(cleanedWords, "****")
				found = true
			}
		}
		if !found {
			cleanedWords = append(cleanedWords, word)
		}
	}
	return strings.Join(cleanedWords, " ")
}
