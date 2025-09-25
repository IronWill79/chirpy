package chirp

import "testing"

func TestCleanChirp(t *testing.T) {
	chirp := "This should pass and remain the same"
	cleanedChirp := CleanChirp(chirp)
	if chirp != cleanedChirp {
		t.Errorf("Result failed, expected: %s, got: %s.", chirp, cleanedChirp)
	}

	chirp = "This should fail and kerfuffle replaced with ****"
	replacedChirp := "This should fail and **** replaced with ****"
	cleanedChirp = CleanChirp(chirp)
	if replacedChirp != cleanedChirp {
		t.Errorf("Result failed, expected: %s, got: %s.", replacedChirp, cleanedChirp)
	}
}
