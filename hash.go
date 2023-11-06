package peda

import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func HashRole(role string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(role), 14)
	return string(bytes), err
}

func CheckRoleHash(role, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(role))
	return err == nil
}
