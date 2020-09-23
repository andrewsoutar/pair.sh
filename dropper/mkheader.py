import os, struct, sys

fmt = "<9sBHLQQ"
def layout():
    return [magic, version, size, checksum & 0xffffffff, offset, length]

magic = b'\x43\x21\xCE\xCFHDR@\x00'
version = 0x00
size = struct.calcsize(fmt) // 4
checksum = 0
offset = struct.calcsize(fmt)
length = os.path.getsize(sys.argv[1])

tmp = struct.pack(fmt, *layout())
checksum -= sum(x[0] for x in struct.iter_unpack("I", tmp))

os.fdopen(1, "wb", closefd=False).write(struct.pack(fmt, *layout()))
