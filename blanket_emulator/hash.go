package blanket_emulator

import (
	xxhash "github.com/OneOfOne/xxhash/native"
)

const initial_salt = uint64(0xbbed475f4c2c4c03)
const order_salt = uint64(0x6e53469168745d93)
const final_salt = uint64(0x12ef5c82f29260c5)
const mem_salt = uint64(0xa66aec150c63e3fe)
const reg_salt = uint64(0x7a1a190d52c2bc81)

func to_byte_array(val uint64) []byte {
	bytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		bytes[i] = byte(val % 0xff)
		val = val / 0xff
	}
	return bytes
}

func fast_hash(salt, val uint64) uint64 {
	return xxhash.Checksum64S(to_byte_array(val), salt)
}

func ReadEventHash(addr uint64) uint64 {
	return fast_hash(initial_salt, addr)
}

func WriteEventHash(addr uint64, value uint64) uint64 {
	return fast_hash(fast_hash(initial_salt, addr), value)
}

func SysEventHash(syscallnum uint64) uint64 {
	return fast_hash(initial_salt, syscallnum)
}

func CallEventHash(arg1 uint64, arg2 uint64) uint64 {
	return fast_hash(fast_hash(initial_salt, arg1), arg2)
}

func GetMem(addr uint64, size int) []byte {
	res := make([]byte, size)
	for i := 0; i < size; i++ {
		res[i] = byte(fast_hash(mem_salt, addr+uint64(i)))
	}
	return res
}

func GetReg(index int) uint64 {
	return fast_hash(reg_salt, uint64(index))
}
