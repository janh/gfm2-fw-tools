#!/usr/bin/env python

import sys
import os
import binascii
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from common import *


def write_data(file_in, filename, size, check_crc, signature):
	crc = 0

	key = RSA.import_key(PUBLIC_KEY)
	h = SHA256.new()
	verifier = pss.new(key)

	with open(filename, "wb") as file_out:
		remaining = size
		while remaining:
			count = 1024 if remaining > 1024 else remaining

			buf = file_in.read(count)
			if len(buf) != count:
				raise Exception("failed to read data")

			file_out.write(buf)
			crc = binascii.crc32(buf, crc)
			h.update(buf)

			remaining -= count

	if crc != check_crc:
		raise Exception(f"CRC32 verification failed: {crc}")

	try:
		verifier.verify(h, signature)
		print("Signature: ok")
	except ValueError:
		raise Exception("Signature verification failed")


def handle_image(file_in, folder_out):
	head = file_in.read(IMG_HEAD_SIZE)
	if len(head) == 0:
		return False
	elif len(head) != IMG_HEAD_SIZE:
		raise Exception("failed to read header")

	img_type = decode_string(get_head_field(head, IMG_FIELD_TYPE))
	print("Image:", img_type)

	filename = os.path.join(folder_out, img_type)

	name = decode_string(get_head_field(head, IMG_FIELD_NAME))
	write_file_ext(filename, "name", bytes(name, "ascii"))
	print("Name:", name.strip())

	unknown1 = decode_string(get_head_field(head, IMG_FIELD_UNKNOWN1))
	if unknown1 != "auto":
		raise Exception(f"unexpected value in unknown1 field: {unknown1}")

	unknown2 = decode_string(get_head_field(head, IMG_FIELD_UNKNOWN2))
	if unknown2 != "auto":
		raise Exception(f"unexpected value in auto2 field: {unknown2}")

	size = decode_int(get_head_field(head, IMG_FIELD_SIZE))
	print("Size:", size)

	version = decode_string(get_head_field(head, IMG_FIELD_VERSION))
	write_file_ext(filename, "version", bytes(version, "ascii"))
	print("Version:", version.strip())

	crc32 = decode_int(get_head_field(head, IMG_FIELD_CRC32))
	print("CRC32:", crc32)

	date = decode_string(get_head_field(head, IMG_FIELD_DATE))
	write_file_ext(filename, "date", bytes(date, "ascii"))
	print("Date:", date.strip())

	signature_length = decode_int(get_head_field(head, IMG_FIELD_SIGNATURE_LENGTH))
	if signature_length != IMG_FIELD_SIGNATURE[1]:
		raise Exception(f"unexpected signature length: {signature_length}")

	signature = get_head_field(head, IMG_FIELD_SIGNATURE)
	write_file_ext(filename, "signature", signature)

	write_data(file_in, filename, size, crc32, signature)

	print()
	return True


def main(filename_in, folder_out):
	file_in = open(filename_in, "rb")

	try:
		os.mkdir(folder_out)
	except FileExistsError:
		pass

	while True:
		res = handle_image(file_in, folder_out)
		if not res:
			break

	file_in.close()


if __name__ == "__main__":
	if len(sys.argv) != 3:
		print(f"Usage: {sys.argv[0]} FILENAME_IN FOLDER_OUT")
		sys.exit(1)

	main(sys.argv[1], sys.argv[2])
