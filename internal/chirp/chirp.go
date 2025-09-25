package chirp

import "strings"

var profanities = []string{"kerfuffle", "sharbert", "fornax"}

type Chirp struct {
	Body string `json:"body"`
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
