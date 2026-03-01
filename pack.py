#!/usr/bin/env python

import sys
import os
import binascii

from common import *


def write_data(file_out, filename):
	crc = 0
	size = 0

	with open(filename, "rb") as file_in:
		while buf := file_in.read():
			file_out.write(buf)

			crc = binascii.crc32(buf, crc)
			size += len(buf)

	return crc, size


def add_image(file_out, img_type, filename):
	print(f"Adding image {img_type}")

	head = bytearray(IMG_HEAD_SIZE)

	field_type = encode_string(img_type, IMG_FIELD_TYPE)
	set_head_field(head, IMG_FIELD_TYPE, field_type)

	name = read_file_ext(filename, "name").decode("ascii")
	field_name = encode_string(name, IMG_FIELD_NAME)
	set_head_field(head, IMG_FIELD_NAME, field_name)

	field_unknown1 = encode_string("auto", IMG_FIELD_UNKNOWN1)
	set_head_field(head, IMG_FIELD_UNKNOWN1, field_unknown1)

	field_unknown2 = encode_string("auto", IMG_FIELD_UNKNOWN2)
	set_head_field(head, IMG_FIELD_UNKNOWN2, field_unknown2)

	version = read_file_ext(filename, "version").decode("ascii")
	field_version = encode_string(version, IMG_FIELD_VERSION)
	set_head_field(head, IMG_FIELD_VERSION, field_version)

	date = read_file_ext(filename, "date").decode("ascii")
	field_date = encode_string(date, IMG_FIELD_DATE)
	set_head_field(head, IMG_FIELD_DATE, field_date)

	signature = read_file_ext(filename, "signature")
	signature_length = len(signature)
	if signature_length != IMG_FIELD_SIGNATURE[1]:
		raise Exception(f"unexpected signature length {signature_length}")

	field_signature_length = encode_int(signature_length, IMG_FIELD_SIGNATURE_LENGTH)
	set_head_field(head, IMG_FIELD_SIGNATURE_LENGTH, field_signature_length)

	set_head_field(head, IMG_FIELD_SIGNATURE, signature)

	offset_head = file_out.tell()
	file_out.seek(IMG_HEAD_SIZE, os.SEEK_CUR)
	crc32, size = write_data(file_out, filename)
	offset_end = file_out.tell()

	field_size = encode_int(size, IMG_FIELD_SIZE)
	set_head_field(head, IMG_FIELD_SIZE, field_size)

	field_crc32 = encode_int(crc32, IMG_FIELD_CRC32)
	set_head_field(head, IMG_FIELD_CRC32, field_crc32)

	file_out.seek(offset_head)
	file_out.write(head)
	file_out.seek(offset_end)


def main(folder_in, filename_out):
	file_out = open(filename_out, "wb")

	if not os.path.isdir(folder_in):
		raise Exception("folder does not exist")

	for img_type in ["rootfs", "lib"]:
		filename = os.path.join(folder_in, img_type)
		if os.path.exists(filename):
			add_image(file_out, img_type, filename)

	file_out.close()


if __name__ == "__main__":
	if len(sys.argv) != 3:
		print(f"Usage: {sys.argv[0]} FOLDER_IN FILENAME_OUT")
		sys.exit(1)

	main(sys.argv[1], sys.argv[2])
