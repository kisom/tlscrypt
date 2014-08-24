package tlscrypt

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"testing"
)

type user struct {
	Priv *rsa.PrivateKey
	Pub  *x509.Certificate
}

var alice, bob user

func TestLoadKeys(t *testing.T) {
	var err error

	in, err := ioutil.ReadFile("testdata/alice.pem")
	if err != nil {
		t.Fatalf("%v", err)
	}

	alice.Pub, err = LoadCertificate(in)
	if err != nil {
		t.Fatalf("%v", err)
	}

	in, err = ioutil.ReadFile("testdata/alice.key")
	if err != nil {
		t.Fatalf("%v", err)
	}

	alice.Priv, err = LoadPrivateKey(in)
	if err != nil {
		t.Fatalf("%v", err)
	}

	in, err = ioutil.ReadFile("testdata/bob.pem")
	if err != nil {
		t.Fatalf("%v", err)
	}

	bob.Pub, err = LoadCertificate(in)
	if err != nil {
		t.Fatalf("%v", err)
	}

	in, err = ioutil.ReadFile("testdata/bob.key")
	if err != nil {
		t.Fatalf("%v", err)
	}

	bob.Priv, err = LoadPrivateKey(in)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

var testSecured []byte
var testMessage = []byte("Why is a raven like a writing desk?")

func TestEncrypt(t *testing.T) {
	var ok bool
	testSecured, ok = Encrypt(alice.Priv, bob.Pub, testMessage)
	if !ok {
		t.Fatal("Encryption failed")
	}
}

func TestDecrypt(t *testing.T) {
	decrypted, ok := Decrypt(bob.Priv, alice.Pub, testSecured)
	if !ok {
		t.Fatal("Decryption failed")
	}

	if !bytes.Equal(decrypted, testMessage) {
		t.Fatalf("Decrypted message was\n\t%x\nbut expected\n\t%x\n",
			decrypted, testMessage)
	}
}
