-- name: UpgradeUser :exec
UPDATE users
SET is_chirpy_red = true
WHERE users.id = $1;