package validation

type ChirpValidationError struct {
	Err string `json:"error"`
}

type ChirpValidationSuccess struct {
	CleanedBody string `json:"cleaned_body"`
}
