package encrypted

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// BackupCipher is the encryption field of an encrypted backup.
const BackupCipher = "aes-256-gcm"

var backupAAD = []byte("secret-manager backup")

// ErrBackupKey is returned when an encrypted backup cannot be decrypted.
var ErrBackupKey = errors.New("cannot decrypt backup, wrong backup key?")

type backupEnvelope struct {
	Encryption string `json:"encryption"`
	Data       string `json:"data"`
}

// SealBackup encrypts a backup document with key into a JSON envelope
// {"encryption": "aes-256-gcm", "data": "<base64>"}.
func SealBackup(key, doc []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(backupEnvelope{Encryption: BackupCipher, Data: base64.StdEncoding.EncodeToString(seal(aead, doc, backupAAD))})
}

// IsEncryptedBackup reports whether raw is an envelope made by SealBackup.
func IsEncryptedBackup(raw []byte) bool {
	var env backupEnvelope
	return json.Unmarshal(raw, &env) == nil && env.Encryption != ""
}

// OpenBackup returns the backup document sealed in raw by SealBackup.
func OpenBackup(key, raw []byte) ([]byte, error) {
	var env backupEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.Encryption != BackupCipher {
		return nil, errors.New("unsupported backup encryption " + env.Encryption)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	sealed, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, ErrBackupKey
	}
	doc, err := unseal(aead, sealed, backupAAD)
	if err != nil {
		return nil, ErrBackupKey
	}
	return doc, nil
}
