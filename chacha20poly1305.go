package chacha20poly1305

import (
	"crypto/cipher"
    "github.com/Yawning/chacha20"
    "github.com/Yawning/poly1305"
	"errors"
	"encoding/binary"
	"crypto/subtle"
)

type chaCha20Poly1305 struct {
    key [32]byte
}

const (
    nonceSize   = 12
    overhead    = 16
)

var (
    ErrInvalidKey = errors.New("chacha20poly1305: key must be 256 bits wide")
)

func New(key []byte) (cipher.AEAD, error) {
    if len(key) != 32 {
        return nil, ErrInvalidKey
    }
    c := &chaCha20Poly1305{}
    copy(c.key[:], key)
    return c, nil
}


func (c *chaCha20Poly1305) NonceSize() int {
    return nonceSize
}

func (c *chaCha20Poly1305) Overhead() int {
    return overhead
}

func (c *chaCha20Poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
    if len(nonce) != nonceSize {
        panic("chacha20poly1305: incorrect nonce length given")
    }
    
    ret, out := sliceForAppend(dst, len(plaintext) + 16)
    
    ciph, _ := chacha20.NewCipher(c.key[:], nonce)

    poly1305Key := make([]byte, 32)
    ciph.KeyStream(poly1305Key)

    ciph.Seek(1)
    ciph.XORKeyStream(out, plaintext)

    zeros := make([]byte, 16)
    auth, _ := poly1305.New(poly1305Key)
    auth.Write(additionalData)
    if pad1 := (len(additionalData)%16); pad1 != 0 {
        auth.Write(zeros[:16-pad1])
    }
    auth.Write(out[0:len(plaintext)])
    if pad2 := (len(plaintext)%16); pad2 != 0 {
        auth.Write(zeros[:16-pad2])
    }
    binary.LittleEndian.PutUint64(zeros, uint64(len(additionalData)))
    binary.LittleEndian.PutUint64(zeros[8:], uint64(len(plaintext)))
    auth.Write(zeros)

    auth.Sum(out[:len(out)-16])
    return ret
}

var errOpen = errors.New("chacha20poly1305: message authentication failed")

func (c *chaCha20Poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
    if len(nonce) != nonceSize {
        panic("chacha20poly1305: incorrect nonce length given")
    }
    tag := ciphertext[len(ciphertext) - 16:]
    ciphertext = ciphertext[:len(ciphertext) - 16]

    ret, out := sliceForAppend(dst, len(ciphertext))
    
    ciph, _ := chacha20.NewCipher(c.key[:], nonce)

    poly1305Key := make([]byte, 32)
    ciph.KeyStream(poly1305Key)

    zeros := make([]byte, 16)
    auth, _ := poly1305.New(poly1305Key)
    auth.Write(additionalData)
    if pad1 := len(additionalData) % 16; pad1 != 0 {
        auth.Write(zeros[:16-pad1])
    }
    auth.Write(ciphertext)
    if pad2 := len(ciphertext) % 16; pad2 != 0 {
        auth.Write(zeros[:16-pad2])
    }
    binary.LittleEndian.PutUint64(zeros, uint64(len(additionalData)))
    binary.LittleEndian.PutUint64(zeros[8:], uint64(len(ciphertext)))
    auth.Write(zeros)

    computedTag := auth.Sum(nil)

    if subtle.ConstantTimeCompare(tag, computedTag[:]) != 1 {
        for i := range out {
            out[i] = 0
        }
        return nil, errOpen
    }

    ciph.Seek(1)
    ciph.XORKeyStream(out, ciphertext)

    return ret, nil
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
    if total := len(in) + n; cap(in) >= total {
        head = in[:total]
    } else {
        head = make([]byte, total)
        copy(head, in)
    }
    tail = head[len(in):]
    return
}

func roundUpTo16(l int) int {
    if (l % 16) != 0 {
        return ((l / 16) + 1)  * 16
    }
    return l
}
