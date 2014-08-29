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
  'ptr_ind ptr_val str_ind str_len str_val'
)

Patch = collections.namedtuple('Patch',
  'index new_item'
)

def main() :
  parser = argparse.ArgumentParser(description='Unpack a .dex')
  parser.add_argument('-f', '--foo', dest='dexfile', action='store',
                      help='path to dex file')
  argdata = parser.parse_args(sys.argv[1:]) # python *.py arg1 arg2
  
  with open(argdata.dexfile, 'rw+') as f:
    header = ext_header(f)
    endian = True
    string_ids = ext_section(f, header['string_ids_size'], header['string_ids_off'] )
    data       = ext_section(f, header['data_size']      , header['data_off']       )
    strings = get_strings(string_ids, data)
    for i in range(0, len(strings)):
      print "%d: %d - %s" % (i, endian_to_dec(strings[i]['ptr_val']), strings[i]['str_val'])
    patches = []
    patches.append(replace_index(strings, 1, 'hello'))
    patches.append(replace_index(strings, 23, 'goodbye'))
    print "before %s" % endian_to_dec(strings[40]['ptr_val'])
    apply_patches(strings, patches)
    print "after %s" % endian_to_dec(strings[40]['ptr_val']) 
    for i in range(0, len(strings)):
      print "%d: %d - %s" % (i, endian_to_dec(strings[i]['ptr_val']), strings[i]['str_val'])
    
def apply_patches(strings, patches):
  for i in range(0, len(strings)):
    string = strings[i]
    for patch in patches:
      if endian_to_dec(string['ptr_val']) > endian_to_dec(patch['new_item']['ptr_val']):
        string['ptr_val'] = dec_to_endian(endian_to_dec(string['ptr_val']) + patch['bump'])
        string['str_ind'] += patch['bump']
      if i == patch['index']:  
        string['str_val'] = patch['new_item']['str_val']
        string['str_len'] = patch['new_item']['str_len']

def replace_string(strings, find, replace):
  find_index = 0
  return replace_index(strings, find_index, replace)
  
def replace_index(strings, index, replace):
  old_item = strings[index]
  new_item = { 'ptr_ind':old_item['ptr_ind'], 
               'ptr_val':old_item['ptr_val'], 
               'str_ind':old_item['str_ind'], 
               'str_len':len(replace), 
               'str_val':replace
             }
  bump = len(replace) - old_item['str_len']
  return { 'index':index,
           'bump':bump,
           'new_item':new_item }
    
  
def get_strings(string_sec, data_sec):
  num_strings = endian_to_dec(string_sec['orig_size'])/4
  strings = []
  for i in range(0, num_strings):
    ptr_val = string_sec['data'][i*4:i*4+4]
    #print endian_to_dec(ptr_val)
    data_ind = endian_to_dec(ptr_val) - endian_to_dec(data_sec['orig_off'])
    #print data_ind
    str_len = struct.unpack('B',data_sec['data'][data_ind:data_ind+1])[0]
    #print str_len
    data_str = data_sec['data'][data_ind+1:data_ind+str_len+1]
    str = { 'ptr_ind':i,
            'ptr_val':ptr_val, 
            'str_ind':data_ind, 
            'str_len':str_len, 
            'str_val':data_str }
    strings.append(str)
  return strings
        
def ext_section(f, size, offset):
  f.seek(endian_to_dec(offset))
  return { 'orig_size':size, 
           'orig_off' :offset, 
           'data'     :f.read(endian_to_dec(size)) }

def ext_header(f):
  f.seek(32)
  header = {
    'file_size'       : f.read(4),
    'header_size'     : f.read(4),
    'endian_tag'      : f.read(4),
    'link_size'       : f.read(4),
    'link_off'        : f.read(4),
    'map_off'         : f.read(4),
    'string_ids_size' : f.read(4),
    'string_ids_off'  : f.read(4),
    'type_ids_size'   : f.read(4),
    'type_ids_off'    : f.read(4),
    'proto_ids_size'  : f.read(4),
    'proto_ids_off'   : f.read(4),
    'field_ids_size'  : f.read(4),
    'field_ids_off'   : f.read(4),
    'method_ids_size' : f.read(4),
    'method_ids_off'  : f.read(4),
    'class_defs_size' : f.read(4),
    'class_defs_off'  : f.read(4),
    'data_size'       : f.read(4),
    'data_off'        : f.read(4)
  }
  return header

def endian_to_dec(value):
  endian = True
  ness = '<L' if endian else '>L'
  return struct.unpack(ness, value)[0]
  
def dec_to_endian(value):
  endian = True
  ness = '<L' if endian else '>L'
  return struct.pack(ness, value)
  
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
