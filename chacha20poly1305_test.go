package chacha20poly1305

import (
	"testing"
	"bytes"
	"crypto/cipher"
	"crypto/aes"
)

func TestChaCha20Poly1305(t *testing.T) {
    plainText := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
    AAD := []byte{0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7}
    Key := make([]byte, 32)
    for i := range Key {
        Key[i] = 0x80 + byte(i)
    }
    Nonce := []byte{0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47}
    tag := []byte{0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91}
    
    c, err := New(Key)
    if err != nil {
        t.Error(err)
    }
    cipherText := c.Seal(nil, Nonce, plainText, AAD)
    estimatedTag := cipherText[len(cipherText) - 16:]
    if !bytes.Equal(estimatedTag, tag) {
        t.Errorf("invalid tag")
    }
    c, err = New(Key)
    if err != nil {
        t.Error(err)
    }

    estimatedPlaintext, err := c.Open(nil, Nonce, cipherText, AAD)
    if err != nil {
        t.Error(err)
    }
    if !bytes.Equal(estimatedPlaintext, plainText) {
        t.Errorf("invalid plaintext")
    }
}

func doEncryptBench(b *testing.B, kb int64, newFunc func ([]byte) (cipher.AEAD, error)) {
    B := 1024 * kb
    key := make([]byte, 32)
    nonce := make([]byte, 12)
    additionalData := make([]byte, 16)
    buf := make([]byte, B, B + 16)
    aead, err := newFunc(key)
    if err != nil {
        b.Fatal(err)
    }
    b.SetBytes(B)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        aead.Seal(buf[:0], nonce, buf, additionalData)
    }

}

func BenchmarkChacha20Poly1305_Encrypt_1k(b *testing.B) {
    doEncryptBench(b, 1, New)
}
func BenchmarkChacha20Poly1305_Encrypt_2k(b *testing.B) {
    doEncryptBench(b, 2, New)
}
func BenchmarkChacha20Poly1305_Encrypt_4k(b *testing.B) {
    doEncryptBench(b, 4, New)
}
func BenchmarkChacha20Poly1305_Encrypt_8k(b *testing.B) {
    doEncryptBench(b, 8, New)
}
func BenchmarkChacha20Poly1305_Encrypt_16k(b *testing.B) {
    doEncryptBench(b, 16, New)
}
func BenchmarkChacha20Poly1305_Encrypt_32k(b *testing.B) {
    doEncryptBench(b, 32, New)
}
func BenchmarkChacha20Poly1305_Encrypt_64k(b *testing.B) {
    doEncryptBench(b, 64, New)
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
    c, _ := aes.NewCipher(key)
    return cipher.NewGCM(c)
}

func BenchmarkAES256GCM_Encrypt_1k(b *testing.B) {
    doEncryptBench(b, 1, newAESGCM)
}
func BenchmarkAES256GCM_Encrypt_2k(b *testing.B) {
    doEncryptBench(b, 2, newAESGCM)
}
func BenchmarkAES256GCM_Encrypt_4k(b *testing.B) {
    doEncryptBench(b, 4, newAESGCM)
}
func BenchmarkAES256GCM_Encrypt_8k(b *testing.B) {
    doEncryptBench(b, 8, newAESGCM)
}
func BenchmarkAES256GCM_Encrypt_16k(b *testing.B) {
    doEncryptBench(b, 16, newAESGCM)
}
func BenchmarkAES256GCM_Encrypt_32k(b *testing.B) {
    doEncryptBench(b, 32, newAESGCM)
}
func BenchmarkAES256GCM_Encrypt_64k(b *testing.B) {
    doEncryptBench(b, 64, newAESGCM)
}
