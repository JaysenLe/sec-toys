import sys
import os
import argparse
import collections
import binascii
import struct

Header = collections.namedtuple('Header',
	'file_size header_size endian_tag link_size link_off map_off string_ids_size string_ids_off type_ids_size type_ids_off proto_ids_size proto_ids_off field_ids_size field_ids_off method_ids_size method_ids_off class_defs_size class_defs_off data_size data_off'
)

Section = collections.namedtuple('Section',
  'orig_size orig_off data'
)


# ptr_ind vs ptr_off
# absolute off? relative off?
# for now just get index and relative_off
# data_off is relative offset
String = collections.namedtuple('String', 
  'ptr_ind ptr_val data_off data_len data_val'
)

def main() :
  parser = argparse.ArgumentParser(description='Unpack a .dex')
  parser.add_argument('-f', '--foo', dest='dexfile', action='store',
                      help='path to dex file')
  argdata = parser.parse_args(sys.argv[1:])
  
  with open(argdata.dexfile, 'rw+') as f:
    header = ext_header(f)
    endian = True
    string_ids = ext_section(f, header.string_ids_size, header.string_ids_off )
    data       = ext_section(f, header.data_size      , header.data_off       )
    get_strings_alt(string_ids, data)
  

def get_strings_alt(string_sec, data_sec):
  num_strings = endian_to_dec(string_sec.orig_size)/4
  print "\n%s" % num_strings
  strings = []
  for i in range(0, num_strings):
    ptr_val = string_sec.data[i*4:i*4+4]
    #print endian_to_dec(ptr_val)
    data_off = endian_to_dec(ptr_val) - endian_to_dec(data_sec.orig_off)
    #print data_off
    str_len = struct.unpack('B',data_sec.data[data_off:data_off+1])[0]
    #print str_len
    data_str = data_sec.data[data_off+2:data_off+str_len+2]
    print "%d - %d: %s" % (i, str_len, data_str)
    #str = String(ptr_ind=i, ptr_val=ptr_val, )
    
  return 0
    
    
def get_strings(f, header):
  f.seek(endian_to_dec(header.string_ids_off))
  num_strings = endian_to_dec(header.string_ids_size) / 4
  strings = []
  for i in range(0, num_strings):
    str = String(ptr_ind=i,ptr_off=4*i,ptr_val=f.read(4))
    
    
    
    
  

    
def ext_section(f, size, offset):
  f.seek(endian_to_dec(offset))
  return Section(orig_size=size, orig_off=offset, data=f.read(endian_to_dec(size)))

def ext_header(f):
  f.seek(32)
  header = Header(
    file_size = f.read(4),
    header_size = f.read(4),
    endian_tag = f.read(4),
    link_size = f.read(4),
    link_off = f.read(4),
    map_off = f.read(4),
    string_ids_size = f.read(4),
    string_ids_off = f.read(4),
    type_ids_size = f.read(4),
    type_ids_off = f.read(4),
    proto_ids_size = f.read(4),
    proto_ids_off = f.read(4),
    field_ids_size = f.read(4),
    field_ids_off = f.read(4),
    method_ids_size = f.read(4),
    method_ids_off = f.read(4),
    class_defs_size = f.read(4),
    class_defs_off = f.read(4),
    data_size = f.read(4),
    data_off = f.read(4)
  )
  return header


def endian_to_dec(value):
  endian = True
  ness = '<L' if endian else '>L'
  return struct.unpack(ness, value)[0]
  
def uleb128_decode(data):
    result = 0
    shift = 0
    size = 0
    while True:
        b = ord(data[size])
        size += 1
        result |= (b & 0x7f) << shift
        if b & 0x80 == 0:
            break
        shift += 7
    return result

if __name__ == "__main__":
  main()
