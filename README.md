# tlscrypt

`tlscrypt` encrypts messages using RSA TLS certificates and private
keys. The message is signed with RSASSA-PSS (using SHA-256 as a hash
function), and a random AES128-GCM-SHA256 key is generated. This key
is used to encrypt the message and signature; the key is then encrypted
with RSAES-OAEP using SHA256. This pair is then used as the ciphertext.

This does not supply forward secrecy.
