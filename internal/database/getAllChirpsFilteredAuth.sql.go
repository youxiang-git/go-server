// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: getAllChirpsFilteredAuth.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const getAllChirpsFilteredAuth = `-- name: GetAllChirpsFilteredAuth :many
SELECT id, created_at, updated_at, body, user_id
FROM chirps
WHERE user_id = $1
ORDER BY created_at
`

func (q *Queries) GetAllChirpsFilteredAuth(ctx context.Context, userID uuid.UUID) ([]Chirp, error) {
	rows, err := q.db.QueryContext(ctx, getAllChirpsFilteredAuth, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Chirp
	for rows.Next() {
		var i Chirp
		if err := rows.Scan(
			&i.ID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.Body,
			&i.UserID,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
