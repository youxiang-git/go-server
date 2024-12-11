-- name: GetChirpById :one
SELECT *
FROM chirps
WHERE id = $1;