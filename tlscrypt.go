// tlscrypt uses TLS certificates and keys to encrypt and sign
// messages. Messages must be signed, and the signature will be checked
// on decryption. Only RSA keys are supported. Messages are signed using
// RSASSA-PSS SHA-256, and the pair is encrypted with AES-128 in GCM
// mode. The AESGCM key is encrypted with RSAES-OAEP using SHA-256.

package tlscrypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"

	"github.com/kisom/tlscrypt/aesgcm"
)

var (
	// ErrCertificate indicates a non-RSA certificate was supplied.
	ErrCertificate = errors.New("only RSA certificates are supported")

	// ErrPrivateKey indicates a non-RSA private key was supplied.
	ErrPrivateKey = errors.New("only RSA private keys are supported")

	// ErrEncryption indicates that encryption failed.
	ErrEncryption = errors.New("encryption failed")

	// ErrDecryption indicates that decryption failed.
	ErrDecryption = errors.New("decryption failed")
)

type message struct {
	Key    []byte
	Signed []byte
}

type signature struct {
	Message   []byte
	Signature []byte
}

// LoadCertificate loads an X.509 certificate, which can be either in
// PEM or DER format.
func LoadCertificate(in []byte) (*x509.Certificate, error) {
	pub := in

	p, _ := pem.Decode(in)
	if p != nil {
		if p.Type != "CERTIFICATE" {
			return nil, errors.New("invalid certificate")
		}
		pub = p.Bytes
	}

	return x509.ParseCertificate(pub)
}

// LoadPrivateKey loads an RSA private key, which can be either in
// PEM or DER format.
func LoadPrivateKey(in []byte) (*rsa.PrivateKey, error) {
	priv := in

	p, _ := pem.Decode(in)
	if p != nil {
		if p.Type != "PRIVATE KEY" && p.Type != "RSA PRIVATE KEY" {
			return nil, errors.New("invalid certificate")
		}
		priv = p.Bytes
	}

	return x509.ParsePKCS1PrivateKey(priv)
}

// Encrypt signs the message with the private key, and encrypts it to
// the certificate supplied.
func Encrypt(priv *rsa.PrivateKey, cert *x509.Certificate, msg []byte) ([]byte, bool) {
	var pub *rsa.PublicKey
	switch certPub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pub = certPub
	default:
		return nil, false
	}

	var signed = signature{msg, nil}

	h := sha256.New()
	h.Write(msg)

	var err error
	signed.Signature, err = rsa.SignPSS(rand.Reader, priv, crypto.SHA256,
		h.Sum(nil), nil)
	if err != nil {
		return nil, false
	}

	out, err := asn1.Marshal(signed)
	if err != nil {
		return nil, false
	}

	key := aesgcm.NewKey()
	if key == nil {
		return nil, false
	}

	out, ok := aesgcm.Encrypt(key, out)
	if !ok {
		return nil, false
	}

	var message message
	message.Signed = out

	h.Reset()
	message.Key, err = rsa.EncryptOAEP(h, rand.Reader, pub, key, nil)
	if err != nil {
		return nil, false
	}

	out, err = asn1.Marshal(message)
	if err != nil {
		return nil, false
	}

	return out, true
}

// Decrypt decrypts the message using the private key and verifies that
// the signature was made by the certificate.
func Decrypt(priv *rsa.PrivateKey, cert *x509.Certificate, enc []byte) ([]byte, bool) {
	var pub *rsa.PublicKey
	switch certPub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pub = certPub
	default:
		return nil, false
	}

	var message message
	_, err := asn1.Unmarshal(enc, &message)
	if err != nil {
		return nil, false
	}

	h := sha256.New()
	key, err := rsa.DecryptOAEP(h, rand.Reader, priv, message.Key, nil)
	if err != nil {
		return nil, false
	}

	dec, ok := aesgcm.Decrypt(key, message.Signed)
	if !ok {
		return nil, false
	}

	var signed signature
	_, err = asn1.Unmarshal(dec, &signed)
	if err != nil {
		return nil, false
	}

	h.Reset()
	h.Write(signed.Message)
	err = rsa.VerifyPSS(pub, crypto.SHA256, h.Sum(nil), signed.Signature, nil)
	if err != nil {
		return nil, false
	}

	return signed.Message, true
}
