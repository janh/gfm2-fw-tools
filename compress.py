#!/usr/bin/env python

import sys
import os
import gzip

from common import *


def write_initial_header(filename_in, file_in, file_out):
	img_head = file_in.read(IMG_HEAD_SIZE)

	head = bytearray(COMP_HEAD_SIZE)

	pid = read_file_ext(filename_in, "pid").decode("ascii")
	set_head_field(head, COMP_FIELD_PID, encode_string(pid, COMP_FIELD_PID))

	img_crc32 = get_head_field(img_head, IMG_FIELD_CRC32)
	set_head_field(head, COMP_FIELD_IMG_CRC32, img_crc32)

	img_size = get_head_field(img_head, IMG_FIELD_SIZE)
	set_head_field(head, COMP_FIELD_IMG_SIZE, img_size)

	img_date = get_head_field(img_head, IMG_FIELD_DATE)
	set_head_field(head, COMP_FIELD_IMG_DATE, img_date)

	img_version = get_head_field(img_head, IMG_FIELD_VERSION)
	set_head_field(head, COMP_FIELD_IMG_VERSION, img_version)

	file_out.write(head)


def compress(file_in, file_out):
	file_in.seek(0)

	with gzip.GzipFile(filename="", mtime=0, compresslevel=6, fileobj=file_out, mode="wb") as gz:
		while buf := file_in.read(1024):
			gz.write(buf)

	# set OS field in gzip header to produce identical output to original firmware file
	file_out.seek(COMP_HEAD_SIZE + 9)
	file_out.write(b"\x03")


def update_size(file_out):
	file_out.seek(0, os.SEEK_END)
	size = file_out.tell()

	file_out.seek(COMP_FIELD_FILE_SIZE[0])
	file_out.write(encode_int(size, COMP_FIELD_FILE_SIZE))


def update_sha256sum(file_out):
	m = hashlib.sha256()

	file_out.seek(0)
	while buf := file_out.read(1024):
		m.update(buf)

	sha256sum = m.digest()

	file_out.seek(COMP_FIELD_SHA256SUM[0])
	file_out.write(sha256sum)


def main(filename_in, filename_out):
	file_in = open(filename_in, "rb")
	file_out = open(filename_out, "wb+")

	write_initial_header(filename_in, file_in, file_out)
	compress(file_in, file_out)

	file_in.close()

	update_size(file_out)
	update_sha256sum(file_out)

	file_out.close()


if __name__ == "__main__":
	if len(sys.argv) != 3:
		print(f"Usage: {sys.argv[0]} FILENAME_IN FILENAME_OUT")
		sys.exit(1)

	main(sys.argv[1], sys.argv[2])
