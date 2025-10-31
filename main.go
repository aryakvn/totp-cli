package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	storageFile = "totp_store.enc"
	saltSize    = 32
	keySize     = 32
	nonceSize   = 12
)

type TOTPEntry struct {
	Label  string `json:"label"`
	Secret string `json:"secret"`
}

type Storage struct {
	Salt    string       `json:"salt"`
	Entries []TOTPEntry  `json:"entries"`
}

// Generate TOTP code
func generateTOTP(secret string, timeStep int64) (string, error) {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("invalid secret: %v", err)
	}

	counter := time.Now().Unix() / timeStep
	counterBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		counterBytes[i] = byte(counter & 0xff)
		counter >>= 8
	}

	h := hmac.New(sha1.New, key)
	h.Write(counterBytes)
	hash := h.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	truncated := hash[offset : offset+4]
	code := int(truncated[0]&0x7f)<<24 |
		int(truncated[1])<<16 |
		int(truncated[2])<<8 |
		int(truncated[3])

	code = code % 1000000
	return fmt.Sprintf("%06d", code), nil
}

// Get seconds until next TOTP refresh
func getSecondsRemaining(timeStep int64) int64 {
	return timeStep - (time.Now().Unix() % timeStep)
}

// Derive encryption key from password
func deriveKey(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, 100000, keySize, sha256.New)
}

// Encrypt data using AES-GCM
func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt data using AES-GCM
func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Read password from terminal
func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(password), nil
}

// Load storage from file
func loadStorage(password string) (*Storage, []byte, error) {
	data, err := os.ReadFile(storageFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Create new storage with random salt
			salt := make([]byte, saltSize)
			if _, err := rand.Read(salt); err != nil {
				return nil, nil, err
			}
			return &Storage{
				Salt:    hex.EncodeToString(salt),
				Entries: []TOTPEntry{},
			}, salt, nil
		}
		return nil, nil, err
	}

	// First 64 chars are hex-encoded salt
	if len(data) < 64 {
		return nil, nil, fmt.Errorf("invalid storage file")
	}

	saltHex := string(data[:64])
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, nil, err
	}

	key := deriveKey([]byte(password), salt)
	decrypted, err := decrypt(data[64:], key)
	if err != nil {
		return nil, nil, fmt.Errorf("incorrect password or corrupted file")
	}

	var storage Storage
	if err := json.Unmarshal(decrypted, &storage); err != nil {
		return nil, nil, err
	}

	storage.Salt = saltHex
	return &storage, salt, nil
}

// Save storage to file
func saveStorage(storage *Storage, password string, salt []byte) error {
	jsonData, err := json.Marshal(storage)
	if err != nil {
		return err
	}

	key := deriveKey([]byte(password), salt)
	encrypted, err := encrypt(jsonData, key)
	if err != nil {
		return err
	}

	// Prepend salt as hex
	output := append([]byte(storage.Salt), encrypted...)
	return os.WriteFile(storageFile, output, 0600)
}

func main() {
	// CLI flags
	tokenFlag := flag.String("token", "", "TOTP secret to generate code for")
	silentFlag := flag.Bool("s", false, "Silent mode (only output code)")
	
	flag.Parse()

	// Handle direct token generation
	if *tokenFlag != "" {
		code, err := generateTOTP(*tokenFlag, 30)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if *silentFlag {
			fmt.Println(code)
		} else {
			remaining := getSecondsRemaining(30)
			now := time.Now()
			validUntil := now.Add(time.Duration(remaining) * time.Second)
			fmt.Printf("%s valid until %s (%d seconds)\n", 
				code, validUntil.Format("15:04:05"), remaining)
		}
		return
	}

	// Interactive mode
	fmt.Println("TOTP Manager")
	fmt.Println("1. Add TOTP")
	fmt.Println("2. Get TOTP")
	fmt.Println("3. List TOTPs")
	fmt.Println("4. Delete TOTP")
	fmt.Println("5. Exit")
	fmt.Print("\nSelect option: ")

	var choice int
	fmt.Scanln(&choice)

	password, err := readPassword("Enter master password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
		os.Exit(1)
	}

	storage, salt, err := loadStorage(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading storage: %v\n", err)
		os.Exit(1)
	}

	switch choice {
	case 1: // Add TOTP
		var label, secret string
		fmt.Print("Enter label: ")
		fmt.Scanln(&label)
		fmt.Print("Enter TOTP secret: ")
		fmt.Scanln(&secret)

		storage.Entries = append(storage.Entries, TOTPEntry{
			Label:  label,
			Secret: secret,
		})

		if err := saveStorage(storage, password, salt); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("TOTP added successfully!")

	case 2: // Get TOTP
		var label string
		fmt.Print("Enter label: ")
		fmt.Scanln(&label)

		for _, entry := range storage.Entries {
			if entry.Label == label {
				code, err := generateTOTP(entry.Secret, 30)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error generating code: %v\n", err)
					os.Exit(1)
				}
				remaining := getSecondsRemaining(30)
				now := time.Now()
				validUntil := now.Add(time.Duration(remaining) * time.Second)
				fmt.Printf("%s valid until %s (%d seconds)\n", 
					code, validUntil.Format("15:04:05"), remaining)
				return
			}
		}
		fmt.Println("Label not found")

	case 3: // List TOTPs
		if len(storage.Entries) == 0 {
			fmt.Println("No TOTPs stored")
			return
		}
		fmt.Println("\nStored TOTPs:")
		for i, entry := range storage.Entries {
			fmt.Printf("%d. %s\n", i+1, entry.Label)
		}

	case 4: // Delete TOTP
		var label string
		fmt.Print("Enter label to delete: ")
		fmt.Scanln(&label)

		newEntries := []TOTPEntry{}
		found := false
		for _, entry := range storage.Entries {
			if entry.Label != label {
				newEntries = append(newEntries, entry)
			} else {
				found = true
			}
		}

		if !found {
			fmt.Println("Label not found")
			return
		}

		storage.Entries = newEntries
		if err := saveStorage(storage, password, salt); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("TOTP deleted successfully!")

	case 5:
		fmt.Println("Goodbye!")
		return

	default:
		fmt.Println("Invalid option")
	}
}