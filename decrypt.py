#!/usr/bin/env python

import sys
import os
import binascii
from Crypto.Cipher import AES

from common import *


def calculate_crc32(file):
	file.seek(0)

	buf = bytearray(file.read(HEAD_SIZE))
	set_head_field(buf, OFFSET_CRC32, 0x20 * b"\x00")
	crc = binascii.crc32(buf)

	while buf := file.read(1024):
		crc = binascii.crc32(buf, crc)

	return crc


def read_header(file):
	head = file.read(HEAD_SIZE)
	if len(head) != HEAD_SIZE:
		raise Exception("failed to read header")

	magic = get_head_field(head, OFFSET_MAGIC)
	if magic != MAGIC:
		raise Exception("unexpected magic value at offset 0xc0")

	size = decode_int(get_head_field(head, OFFSET_FILE_SIZE))

	file.seek(0, os.SEEK_END)
	actual_size = file.tell()

	if size != actual_size:
		raise Exception(f"unexpected file size ({size} != {actual_size})")

	crc = decode_int(get_head_field(head, OFFSET_CRC32))

	actual_crc = calculate_crc32(file)

	if crc != actual_crc:
		raise Exception(f"unexpected CRC32 ({crc} != {actual_crc})")

	iv = get_head_field(head, OFFSET_IV)
	salt = get_head_field(head, OFFSET_SALT)
	payload_size = decode_int(get_head_field(head, OFFSET_PAYLOAD_SIZE))

	return iv, salt, payload_size


def decrypt_image(file_in, file_out, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv=iv[0:16])

	file_in.seek(HEAD_SIZE)
	while buf := file_in.read(1024):
		out = cipher.decrypt(buf)
		file_out.write(out)


def main(filename_in, filename_out):
	file_in = open(filename_in, "rb")

	iv, salt, payload_size = read_header(file_in)
	key = calculate_aes_key(salt, payload_size)

	file_out = open(filename_out, "wb")

	decrypt_image(file_in, file_out, key, iv)
	file_out.truncate(payload_size)

	file_in.close()
	file_out.close()


if __name__ == "__main__":
	if len(sys.argv) != 3:
		print(f"Usage: {sys.argv[0]} FILENAME_IN FILENAME_OUT")
		sys.exit(1)

	main(sys.argv[1], sys.argv[2])
