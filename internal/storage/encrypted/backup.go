package encrypted

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// BackupCipher is the encryption field of an encrypted backup.
const BackupCipher = "argon2id+aes-256-gcm"

var backupAAD = []byte("secret-manager backup")

// ErrBackupPassphrase is returned when an encrypted backup cannot be
// decrypted.
var ErrBackupPassphrase = errors.New("cannot decrypt backup, wrong passphrase?")

// MinBackupPassphraseLength is the shortest passphrase, in bytes, that
// encrypts a backup.
const MinBackupPassphraseLength = 8

// CheckBackupPassphrase reports whether passphrase is long enough to encrypt
// a backup.
func CheckBackupPassphrase(passphrase string) error {
	if len(passphrase) < MinBackupPassphraseLength {
		return fmt.Errorf("backup passphrase must have at least %d characters", MinBackupPassphraseLength)
	}
	return nil
}

// Argon2id cost of new backups, the second recommended option of RFC 9106;
// memory is in KiB.
const (
	backupTime    = 3
	backupMemory  = 64 * 1024
	backupThreads = 4
	maxMemory     = 1024 * 1024
	maxTime       = 16
)

type backupEnvelope struct {
	Encryption string `json:"encryption"`
	Salt       string `json:"salt"`
	Time       uint32 `json:"time"`
	Memory     uint32 `json:"memory"`
	Threads    uint8  `json:"threads"`
	Data       string `json:"data"`
}

// SealBackup encrypts a backup document with a key derived from passphrase
// into a JSON envelope {"encryption": "argon2id+aes-256-gcm", "salt": ...,
// "time": ..., "memory": ..., "threads": ..., "data": "<base64>"}.
func SealBackup(passphrase string, doc []byte) ([]byte, error) {
	if err := CheckBackupPassphrase(passphrase); err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	env := backupEnvelope{Encryption: BackupCipher, Salt: base64.StdEncoding.EncodeToString(salt), Time: backupTime, Memory: backupMemory, Threads: backupThreads}
	aead, err := newAEAD(env.key(passphrase, salt))
	if err != nil {
		return nil, err
	}
	env.Data = base64.StdEncoding.EncodeToString(seal(aead, doc, backupAAD))
	return json.Marshal(env)
}

func (e backupEnvelope) key(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, e.Time, e.Memory, e.Threads, KeySize)
}

// IsEncryptedBackup reports whether raw is an envelope made by SealBackup.
func IsEncryptedBackup(raw []byte) bool {
	var env backupEnvelope
	return json.Unmarshal(raw, &env) == nil && env.Encryption != ""
}

// OpenBackup returns the backup document sealed in raw by SealBackup.
func OpenBackup(passphrase string, raw []byte) ([]byte, error) {
	var env backupEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.Encryption != BackupCipher {
		return nil, errors.New("unsupported backup encryption " + env.Encryption)
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) == 0 || env.Time == 0 || env.Time > maxTime || env.Memory == 0 || env.Memory > maxMemory || env.Threads == 0 {
		return nil, errors.New("backup has invalid key derivation parameters")
	}
	aead, err := newAEAD(env.key(passphrase, salt))
	if err != nil {
		return nil, err
	}
	sealed, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, ErrBackupPassphrase
	}
	doc, err := unseal(aead, sealed, backupAAD)
	if err != nil {
		return nil, ErrBackupPassphrase
	}
	return doc, nil
}
