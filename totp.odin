/*
   totp is an utility to generate time-based one-time passwords.

   Usage:

   echo <KEY> | totp
 */
package main

import "core:crypto/hash"
import "core:crypto/hmac"
import "core:crypto/legacy/sha1"
import "core:encoding/base32"
import "core:encoding/endian"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:time"

hotp :: proc(key: []byte, counter: u64) -> u32 {
	counter_bytes: [8]byte
	endian.unchecked_put_u64be(counter_bytes[:], counter)

	sum: [sha1.DIGEST_SIZE]byte
	hmac.sum(hash.Algorithm.Insecure_SHA1, sum[:], counter_bytes[:], key)

	offset := sum[len(sum)-1] & 0xF
	return (endian.unchecked_get_u32be(sum[offset:offset+4]) & 0x7FFFFFFF) % 1e6
}

totp :: proc(key: []byte) -> u32 {
	return hotp(key, u64(time.time_to_unix(time.now())) / 30)
}

main :: proc() {
	key_buf: [128]byte
	n, read_err := os.read(os.stdin, key_buf[:])
	if read_err != nil {
		fmt.eprintfln("otp: failed to read input: %s", read_err)
		os.exit(1)
	}
	key := string(key_buf[:n])
	key = strings.trim_space(key)

	decoded_key, decode_err := base32.decode(key)
	if decode_err != nil {
		fmt.eprintfln("otp: failed to decode key: %s", decode_err)
		os.exit(1)
	}
	defer delete(decoded_key)

	fmt.printf("%06d\n", totp(decoded_key))
}
