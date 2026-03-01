#!/usr/bin/env python

import sys
import os
import hashlib
import gzip

from common import *


def calculate_sha256sum(file):
	m = hashlib.sha256()

	file.seek(0)

	buf = bytearray(file.read(COMP_HEAD_SIZE))
	set_head_field(buf, COMP_FIELD_SHA256SUM, COMP_FIELD_SHA256SUM[1] * b"\x00")
	m.update(buf)

	while buf := file.read(1024):
		m.update(buf)

	return m.digest()


def check_header(file):
	head = file.read(COMP_HEAD_SIZE)
	if len(head) != COMP_HEAD_SIZE:
		raise Exception("failed to read header")

	size = decode_int(get_head_field(head, COMP_FIELD_FILE_SIZE))

	file.seek(0, os.SEEK_END)
	actual_size = file.tell()

	if size != actual_size:
		raise Exception(f"unexpected file size ({size} != {actual_size})")

	sha256sum = get_head_field(head, COMP_FIELD_SHA256SUM)

	actual_sha256sum = calculate_sha256sum(file)

	if sha256sum != actual_sha256sum:
		raise Exception(f"unexpected SHA256 sum ({sha256sum} != {actual_sha256sum})")

	pid = decode_string(get_head_field(head, COMP_FIELD_PID))

	img_crc32 = decode_int(get_head_field(head, COMP_FIELD_IMG_CRC32))
	img_size = decode_int(get_head_field(head, COMP_FIELD_IMG_SIZE))
	img_date = decode_string(get_head_field(head, COMP_FIELD_IMG_DATE))
	img_version = decode_string(get_head_field(head, COMP_FIELD_IMG_VERSION))

	print("PID:", pid.strip())
	print("Main image CRC32:", img_crc32)
	print("Main image size:", img_size)
	print("Main image date:", img_date.strip())
	print("Main image version:", img_version.strip())

	return pid


def decompress(file_in, file_out):
	file_in.seek(COMP_HEAD_SIZE)

	with gzip.GzipFile(fileobj=file_in, mode="rb") as gz:
		while buf := gz.read(1024):
			file_out.write(buf)


def main(filename_in, filename_out):
	file_in = open(filename_in, "rb")

	pid = check_header(file_in)

	file_out = open(filename_out, "wb")

	write_file_ext(filename_out, "pid", bytes(pid, "ascii"))
	decompress(file_in, file_out)

	file_in.close()
	file_out.close()


if __name__ == "__main__":
	if len(sys.argv) != 3:
		print(f"Usage: {sys.argv[0]} FILENAME_IN FILENAME_OUT")
		sys.exit(1)

	main(sys.argv[1], sys.argv[2])
