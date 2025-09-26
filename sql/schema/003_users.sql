-- +goose Up
ALTER TABLE users
ADD hashed_password TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE users
DROP hashed_password;
