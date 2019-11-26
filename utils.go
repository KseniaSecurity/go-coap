package coap

import (
	"crypto/rand"
	"encoding/binary"
	"hash/crc64"
	"sync/atomic"
)

var tokenIter = uint32(0)

// GenerateToken generates a random token by a given length
func GenerateToken() ([]byte, error) {
	b := make([]byte, MaxTokenSize)
	if MaxTokenSize > 1 {
		_, err := rand.Read(b)
		// Note that err == nil only if we read len(b) bytes.
		if err != nil {
			return nil, err
		}
	} else {
		b[0] = uint8(atomic.AddUint32(&tokenIter, 1) % 0xff)
		return b, nil
	}
	return b, nil
}

var msgIdIter = uint32(0)

// GenerateMessageID generates a message id for UDP-coap
func GenerateMessageID() uint16 {
	return uint16(atomic.AddUint32(&msgIdIter, 1) % 0xffff)
}

// Calculate ETag from payload via CRC64
func CalcETag(payload []byte) []byte {
	if payload != nil {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, crc64.Checksum(payload, crc64.MakeTable(crc64.ISO)))
		return b
	}
	return nil
}
