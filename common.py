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
