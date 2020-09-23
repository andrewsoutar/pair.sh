code = 1
try:
  import ctypes, zlib
  try:
    import mmap
    try:
      ctypes.c_char.from_buffer
    except:
      ctypes.pythonapi.PyObject_AsReadBuffer
  except:
    try:
      ctypes.pythonapi.mmap
    except:
      ctypes.LoadLibrary(ctypes.find_library("c")).mmap
  code = 0
except:
  pass
exit(code)
