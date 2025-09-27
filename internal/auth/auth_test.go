package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var testID = uuid.New()
var testPassword = "testing!"
var testSecret = "testSecret"
var testToken = "testing"

func TestHashPassword(t *testing.T) {
	hashedPassword, err := HashPassword(testPassword)
	assert.NoError(t, err)
	ok, err := CheckPasswordHash(testPassword, hashedPassword)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestValidateToken(t *testing.T) {
	token, err := MakeJWT(testID, testSecret, 5*time.Second)
	assert.NoError(t, err)
	id, err := ValidateJWT(token, testSecret)
	assert.NoError(t, err)
	assert.Equal(t, testID, id)
}

func TestExpiredToken(t *testing.T) {
	token, err := MakeJWT(testID, testSecret, 1*time.Microsecond)
	assert.NoError(t, err)
	_, err = ValidateJWT(token, testSecret)
	assert.Error(t, err)
}

func TestBearerToken(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "Bearer "+testToken)
	token, err := GetBearerToken(headers)
	assert.NoError(t, err)
	assert.Equal(t, token, testToken)
}
