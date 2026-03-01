import hashlib


# encryption header: length 0x140
# offset 0x20, length 0x20: AES256-CBC IV
# offset 0x40, length 0x20: PBKDF2 salt
# offset 0x60, length 0x20: encrypted file size (encoded as string)
# offset 0x80, length 0x20: CRC32 of entire file with zeroed CRC field (encoded as string)
# offset 0xa0, length 0x20: unencrypted payload size (encoded as string)
# offset 0xc0, length 0x2a: magic string

ENC_HEAD_SIZE = 0x140

ENC_FIELD_IV = (0x20, 0x20)
ENC_FIELD_SALT = (0x40, 0x20)
ENC_FIELD_FILE_SIZE = (0x60, 0x20)
ENC_FIELD_CRC32 = (0x80, 0x20)
ENC_FIELD_PAYLOAD_SIZE = (0xa0, 0x20)
ENC_FIELD_MAGIC = (0xc0, 0x2a)


# compression header: length 0x1c0
# offset 0x20, length 0x80: PID (string, see below)
# offset 0xa0, length 0x20: file size (encoded as string)
# offset 0xc0, length 0x20: SHA256 sum of entire file with zeroed SHA256 field
# offset 0xe0, length 0x20: CRC32 of first/main partition in compressed data (string)
# offset 0x100, length 0x20: size of first/main partition in compressed data (string)
# offset 0x120, length 0x20: date of first/main partition in compressed data (string)
# offset 0x140, length 0x20: version of first/main partition in compressed data (string)

COMP_HEAD_SIZE = 0x1c0

COMP_FIELD_PID = (0x20, 0x80)
COMP_FIELD_FILE_SIZE = (0xa0, 0x20)
COMP_FIELD_SHA256SUM = (0xc0, 0x20)
COMP_FIELD_IMG_CRC32 = (0xe0, 0x20)
COMP_FIELD_IMG_SIZE = (0x100, 0x20)
COMP_FIELD_IMG_DATE = (0x120, 0x20)
COMP_FIELD_IMG_VERSION = (0x140, 0x20)


# image partition header: length 0x340
# offset 0x0, length 0x40: type (string: bootloader/kernel/rootfs/lib)
# offset 0x40, length 0x40: name (string, e.g. kernel_rootfs or rootfs_lib)
# offset 0xc0, length 0x20: unknown, maybe related to how/where image is written (always string "auto")
# offset 0x120, length 0x20: unknown, maybe related to how/where image is written (always string "auto")
# offset 0x140, length 0x20: data size (encoded as string)
# offset 0x160, length 0x20: version number (string)
# offset 0x1a0, length 0x20: CRC32 of data (encoded as string)
# offset 0x1c0, length 0x20, date (string, no fixed format)
# offset 0x1e0, length 0x20: signature length (encoded as string, should always be 256)
# offset 0x200, length 0x100: RSA PSS SHA256 signature of data

IMG_HEAD_SIZE = 0x340

IMG_FIELD_TYPE = (0x0, 0x40)
IMG_FIELD_NAME = (0x40, 0x40)
IMG_FIELD_UNKNOWN1 = (0xc0, 0x20)
IMG_FIELD_UNKNOWN2 = (0x120, 0x20)
IMG_FIELD_SIZE = (0x140, 0x20)
IMG_FIELD_VERSION = (0x160, 0x20)
IMG_FIELD_CRC32 = (0x1a0, 0x20)
IMG_FIELD_DATE = (0x1c0, 0x20)
IMG_FIELD_SIGNATURE_LENGTH = (0x1e0, 0x20)
IMG_FIELD_SIGNATURE = (0x200, 0x100)


# PID:
# - 090144.1.0.001: 0000010044485000000000000000000000000000000000000000000000000000000000000000413030310000000000000000100100000000
# - 090165.1.0.009: 0000010044485000000000000000000000000000000000000000000000000000000000000000413030310000000000000000100900000000
# -> bits 4..7: bootloader version
# -> bits 8..13: product
# -> bits 100..103: firmware version


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


def get_head_field(buf, field):
	offset, length = field

	return buf[offset:offset+length]


def set_head_field(buf, field, val):
	offset, length = field

	if length != len(val):
		raise Exception("incorrect header field length")

	buf[offset:offset+length] = val


def decode_string(val):
	return val.rstrip(b"\x00").decode("ascii")


def encode_string(val, field):
	length = field[1]
	if len(val) > length:
		raise Exception(f'value "{val}" too long to encode in {length} bytes')

	padding = b"\x00" * (length - len(val))
	return bytes(val, "ascii") + padding


def decode_int(val):
	return int(decode_string(val))


def encode_int(val, field):
	string = str(val)
	return encode_string(string, field)


def calculate_aes_key(salt, payload_size):
	password = bytearray(0x200)
	password[0:0x100] = PUBLIC_KEY[0:0x100]
	password[0x100:0x12a] = MAGIC
	password[0x12a:0x14a] = encode_int(payload_size, (0, 0x20))

	return hashlib.pbkdf2_hmac("sha256", password, salt, 1000)


def read_file_ext(filename, ext):
	with open(filename + "." + ext, "rb") as file:
		return file.read()


def write_file_ext(filename, ext, data):
	with open(filename + "." + ext, "wb") as file:
		file.write(data)
