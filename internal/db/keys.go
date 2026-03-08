package db

type SigningKey struct {
	KID           string
	PrivateKeyPEM string
	Algorithm     string
	KeyType       string
	Active        bool
}

func (d *DB) GetActiveSigningKey(keyType string) (*SigningKey, error) {
	k := &SigningKey{}
	err := d.QueryRow(
		"SELECT kid, private_key_pem, algorithm, key_type, active FROM signing_keys WHERE active = 1 AND key_type = ?",
		keyType,
	).Scan(&k.KID, &k.PrivateKeyPEM, &k.Algorithm, &k.KeyType, &k.Active)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (d *DB) CreateSigningKey(kid, privateKeyPEM, algorithm, keyType string) error {
	_, err := d.Exec(
		"INSERT INTO signing_keys (kid, private_key_pem, algorithm, key_type) VALUES (?, ?, ?, ?)",
		kid, privateKeyPEM, algorithm, keyType,
	)
	return err
}

