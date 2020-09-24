import binascii
import ctypes
import os
import sys
import zlib

def find_libc_fn(name, restype):
  try:
    fn = getattr(ctypes.pythonapi, name)
  except:
    fn = getattr(ctypes.LoadLibrary(ctypes.find_library("c")), name)
  fn.restype = restype
  return fn

tramp_file = os.fdopen(int(sys.argv[2]), "rb")
tramp = zlib.decompress(binascii.a2b_base64(tramp_file.read()), -15)
tramp_file.close()
os.close(int(sys.argv[1]))

try:
  import mmap
  try:
    exec_map = ctypes.byref(ctypes.c_char.from_buffer(mmap.mmap(-1, len(tramp), prot=7)))
  except:
    exec_map = ctypes.POINTER(ctypes.c_char)()
    ctypes.pythonapi.PyObject_AsReadBuffer(
      ctypes.py_object(mmap.mmap(-1, len(tramp), prot=7)),
      ctypes.byref(ret),
      ctypes.byref(ctypes.c_size_t())
    )
except:
  exec_map = find_libc_fn("mmap", ctypes.c_void_p)(
    None, ctypes.c_size_t(len(tramp)), 7, 34, -1, ctypes.c_longlong(0))

ctypes.memmove(exec_map, tramp, len(tramp))

addr = ctypes.addressof(ctypes.cast(exec_map, ctypes.POINTER(ctypes.c_char * len(tramp)))[0])
loader_start = int(sys.argv[3], 16)
loader = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(addr + loader_start)

argv = [x.encode() for x in sys.argv[5:]]
envp = [("%s=%s" % (k, v)).encode() for k, v in os.environ.items()]
c_argv = (ctypes.c_char_p * (len(argv) + 1))(*argv, None)
c_envp = (ctypes.c_char_p * (len(envp) + 1))(*envp, None)
try:
  vdso_base = find_libc_fn("getauxval", ctypes.c_ulong)(33)
except:
  vdso_base = 0

loader(c_argv, c_envp, ctypes.c_void_p(vdso_base))
