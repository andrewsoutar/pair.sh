#!/usr/bin/env python
import binascii, sys, zlib

def do_compression(in_file, out_file):
  def write_base64(data):
    out_file.write(binascii.b2a_base64(data, newline=False).decode('ascii'))
  compressobj = zlib.compressobj(level=9, wbits=-15)
  overflow = b""
  for block in iter(lambda: in_file.read(4096), b""):
    compressed = overflow + compressobj.compress(block)
    leftover = len(compressed) % 4
    write_base64(compressed[:-leftover])
    overflow = compressed[-leftover:]
  write_base64(compressobj.compress(overflow) + compressobj.flush())
  out_file.write("\n")

with open(sys.argv[1], "rb") as in_file:
  if len(sys.argv) > 2:
    with open(sys.argv[2], "w") as out_file:
      do_compression(in_file, out_file)
  else:
    do_compression(in_file, sys.stdout)
