package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var testID = uuid.New()
var testSecret = "testSecret"
var testPassword = "testing!"

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
