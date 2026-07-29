package vless

import "github.com/google/uuid"

type User struct {
	ID   uuid.UUID
	Name string
	Flow string
}
