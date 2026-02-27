#!/usr/bin/env python

import sys
import os
import binascii
import hashlib
from Crypto.Cipher import AES


# header format: length 0x140
# offset 0x20, length 0x20: AES256-CBC IV
# offset 0x40, length 0x20: PBKDF2 salt
# offset 0x60, length 0x20: encrypted file size (encoded as string)
# offset 0x80, length 0x20: CRC32 of entire file with zeroed CRC field (encoded as string)
# offset 0xa0, length 0x20: unencrypted payload size (encoded as string)
# offset 0xc0, length 0x2a: magic string


HEAD_SIZE = 0x140

PUBLIC_KEY = \
	b"-----BEGIN PUBLIC KEY-----\n" + \
	b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqEZkeCLVN+smJ0C4WFH\n" + \
	b"bH6OkgDY7XXywRkhsyqIDJ2HAGaaDQ4uMPgqyIvUnGY08XOXi0ptlX73ll+6qlxr\n" + \
	b"hhFZnMfCguhUgILrydqSMZmGjwbU1TZJIC9eM/QOQUAbvwUP9GsxOriEAK3/FpHQ\n" + \
	b"sz7tZXXv7zzrn0oKba7YHsX8o5HUR5nB6gQQdDpkqWOdcIkiaRKSODnjS19zCzqi\n" + \
	b"l/mZ5OPOu+vAbF32IbhzcRu++VrHJ1PpbGNCK+Xj6Se+h4OWgnuGkcrMJNHh1Smi\n" + \
	b"yANXFyqekMIVBtgXdgez1x6xuoQKY4cDZJMGiM14eanhZQSImgIYwF8ijbxjW+se\n" + \
	b"bQIDAQAB\n" + \
	b"-----END PUBLIC KEY-----\n"

MAGIC = b"534320200402aaa567787970746562366c6dsc5343"


def calculate_crc32(file):
	file.seek(0)
	crc = 0
	buf = bytearray(file.read(HEAD_SIZE))
	buf[0x80:0xa0] = 0x20 * b"\x00"
	while buf:
		crc = binascii.crc32(buf, crc)
		buf = file.read(1024)
	return crc


def read_header(file):
	head = file.read(HEAD_SIZE)
	if len(head) != HEAD_SIZE:
		raise Exception("failed to read header")

	magic = head[0xc0:0xc0+len(MAGIC)]
	if magic != MAGIC:
		raise Exception("unexpected magic value at offset 0xc0")

	size = head[0x60:0x80]
	size_int = int(size.rstrip(b"\x00"))

	file.seek(0, os.SEEK_END)
	actual_size = file.tell()

	if size_int != actual_size:
		raise Exception(f"unexpected file size ({size_int} != {actual_size})")

	crc = head[0x80:0xa0]
	crc_uint = int(crc.rstrip(b"\x00"))

	actual_crc = calculate_crc32(file)

	if crc_uint != actual_crc:
		raise Exception(f"unexpected CRC32 ({crc_uint} != {actual_crc})")

	iv = head[0x20:0x40]
	salt = head[0x40:0x60]
	payload_size = head[0xa0:0xc0]

	payload_size_int = int(payload_size.rstrip(b"\x00"))

	return iv, salt, payload_size, payload_size_int


def calculate_aes_key(salt, size):
	password = bytearray(0x200)
	password[0:0x100] = PUBLIC_KEY[0:0x100]
	password[0x100:0x100+len(MAGIC)] = MAGIC
	password[0x12a:0x14a] = size

	return hashlib.pbkdf2_hmac("sha256", password, salt, 1000)


def decrypt_image(file_in, file_out, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv=iv[0:16])

	file_in.seek(HEAD_SIZE)
	buf = file_in.read(1024)
	while buf:
		out = cipher.decrypt(buf)
		file_out.write(out)
		buf = file_in.read(1024)


def main(filename_in, filename_out):
	file_in = open(filename_in, "rb")

	iv, salt, size, size_int = read_header(file_in)
	key = calculate_aes_key(salt, size)

	file_out = open(filename_out, "wb")

	decrypt_image(file_in, file_out, key, iv)
	file_out.truncate(size_int)

	file_in.close()
	file_out.close()


if __name__ == "__main__":
	if len(sys.argv) != 3:
		print(f"Usage: {sys.argv[0]} FILENAME_IN FILENAME_OUT")
		sys.exit(1)

	main(sys.argv[1], sys.argv[2])
