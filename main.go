package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

func init() {
	// Open a database connection
	var err error
	db, err = sql.Open("mysql", "root:@tcp(localhost:3306)/task5")
	if err != nil {
		log.Fatal(err)
	}

	// Check if the connection is established
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Database connected")

	// Create tables if they do not exist
	createTables()
}

// CreateTables creates the necessary tables if they do not exist
func createTables() {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(50) PRIMARY KEY,
			username VARCHAR(50) UNIQUE,
			password VARCHAR(100)
		);
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS images (
			id VARCHAR(50) PRIMARY KEY,
			user_id VARCHAR(50),
			file VARCHAR(255),
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
	`)
	if err != nil {
		log.Fatal(err)
	}
}

// User struct represents a user in the system.
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Image struct represents an image in the system.
type Image struct {
	ID     string `json:"id"`
	UserID string `json:"userId"`
	File   string `json:"file"`
}

var sessions = make(map[string]string)

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/register", Register).Methods("POST")
	r.HandleFunc("/login", Login).Methods("POST")
	r.HandleFunc("/logout", Logout).Methods("POST")
	r.HandleFunc("/post-image", PostImage).Methods("POST")

	http.Handle("/", r)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func Register(w http.ResponseWriter, r *http.Request) {
	var newUser User
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if the username is already taken
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", newUser.Username).Scan(&count)
	if err != nil {
		http.Error(w, "Error checking username availability", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "Username is already taken", http.StatusConflict)
		return
	}

	// Hash the password before storing it
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	newUser.ID = fmt.Sprint(time.Now().UnixNano())
	newUser.Password = string(hashedPassword)

	// Insert user into the database
	_, err = db.Exec("INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
		newUser.ID, newUser.Username, newUser.Password)
	if err != nil {
		http.Error(w, "Error inserting user into the database", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var user User
	err = db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", loginRequest.Username).
		Scan(&user.ID, &user.Username, &user.Password)
	if err == sql.ErrNoRows {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Error querying the database", http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginRequest.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create a session ID and store it in the sessions map
	sessionID := fmt.Sprint(time.Now().UnixNano())
	sessions[sessionID] = user.ID

	response := map[string]string{"sessionID": sessionID}
	json.NewEncoder(w).Encode(response)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	var logoutRequest struct {
		SessionID string `json:"sessionID"`
	}

	err := json.NewDecoder(r.Body).Decode(&logoutRequest)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if the session ID exists and delete it
	if _, exists := sessions[logoutRequest.SessionID]; exists {
		delete(sessions, logoutRequest.SessionID)
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Invalid session ID", http.StatusUnauthorized)
}

func PostImage(w http.ResponseWriter, r *http.Request) {
	var postImageRequest Image
	err := json.NewDecoder(r.Body).Decode(&postImageRequest)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if the user is authenticated
	userID, authenticated := sessions[postImageRequest.UserID]
	if !authenticated {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	// Check if the user ID matches the session ID
	if userID != postImageRequest.UserID {
		http.Error(w, "Invalid user ID", http.StatusUnauthorized)
		return
	}

	// Insert image into the database
	_, err = db.Exec("INSERT INTO images (id, user_id, file) VALUES (?, ?, ?)",
		postImageRequest.ID, postImageRequest.UserID, postImageRequest.File)
	if err != nil {
		http.Error(w, "Error inserting image into the database", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
