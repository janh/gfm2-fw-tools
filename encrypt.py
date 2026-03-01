#!/usr/bin/env python

import sys
import os
import binascii
import secrets
from Crypto.Cipher import AES

from common import *


def generate_random_value(field):
	return secrets.token_bytes(field[1])


def calculate_total_size(payload_size):
	remainder = payload_size % 16
	padding = 16 - remainder if remainder != 0 else 0
	return ENC_HEAD_SIZE + payload_size + padding


def write_initial_header(file_out, iv, salt, payload_size):
	head = bytearray(ENC_HEAD_SIZE)

	field_size = encode_int(calculate_total_size(payload_size), ENC_FIELD_FILE_SIZE)
	field_payload_size = encode_int(payload_size, ENC_FIELD_PAYLOAD_SIZE)

	set_head_field(head, ENC_FIELD_IV, iv)
	set_head_field(head, ENC_FIELD_SALT, salt)
	set_head_field(head, ENC_FIELD_FILE_SIZE, field_size)
	set_head_field(head, ENC_FIELD_PAYLOAD_SIZE, field_payload_size)
	set_head_field(head, ENC_FIELD_MAGIC, MAGIC)

	file_out.write(head)

	crc = binascii.crc32(head)
	return crc


def encrypt_block(file_out, buf, cipher, crc):
	remainder = len(buf) % 16
	if remainder != 0:
		count = 16 - remainder
		buf += int.to_bytes(count) * count

	out = cipher.encrypt(buf)

	file_out.write(out)
	crc = binascii.crc32(out, crc)

	return crc


def encrypt_image(file_in, file_out, key, iv, crc):
	cipher = AES.new(key, AES.MODE_CBC, iv=iv[0:16])

	file_in.seek(0)

	while buf := file_in.read(1024):
		crc = encrypt_block(file_out, buf, cipher, crc)

	return crc


def write_crc(file_out, crc):
	file_out.seek(ENC_FIELD_CRC32[0])
	file_out.write(encode_int(crc, ENC_FIELD_CRC32))


def main(filename_in, filename_out):
	file_in = open(filename_in, "rb")

	file_in.seek(0, os.SEEK_END)
	payload_size = file_in.tell()

	iv = generate_random_value(ENC_FIELD_IV)
	salt = generate_random_value(ENC_FIELD_SALT)

	file_out = open(filename_out, "wb")

	crc = write_initial_header(file_out, iv, salt, payload_size)

	key = calculate_aes_key(salt, payload_size)

	crc = encrypt_image(file_in, file_out, key, iv, crc)
	write_crc(file_out, crc)

	file_in.close()
	file_out.close()


if __name__ == "__main__":
	if len(sys.argv) != 3:
		print(f"Usage: {sys.argv[0]} FILENAME_IN FILENAME_OUT")
		sys.exit(1)

	main(sys.argv[1], sys.argv[2])
