#!/usr/bin/env python

"""
searchbin.py -p PATTERN [FILE [FILE...]]
searchbin.py -f FILE [FILE [FILE...]]

examples:
./searchbin.py -p "0xCCDD??FF" myfile.exe
Searches for the pattern "CCDD??FF" in myfile.exe, where ?? can be any byte value.

./searchbin.py -f pattern.bin myfile.exe
Takes the binary file pattern.bin, and searches for an exact match within myfile.exe.


+Minimum Py2.7 required for argparse library
+Features: no compiling, less code, files of unlimited size, similar in usage to grep
+keywords binary grep search seek find fast

license: BSD 2-Clause License, 2012, Sepero
license: http://www.opensource.org/licenses/BSD-2-Clause
"""

VERSION = "0.1"

import sys, signal

def _exit_error(code, option="", err=None):
  """
  Error information is kept here for the purposes of easier management and possibly language tranlation.
  Returns nothing.  All calls exit the program, error status 128.
  """
  error_codes = {
    '2patterns':
      "Cannot search for both a binary file and hex pattern. '-p -f'",
    '0patterns':
      "No pattern to search for was supplied. '-p -f'",
    'decode':
      "The pattern string is invalid.\n" + str(option),
    'nohex':
      "The search pattern must start with '0x' for future compatibility",
    'bsize':
      "The buffer size must be at least %s bytes." % str(option),
    'sizes':
      "Size parameters (-b -s -e -m) must be in decimal format.",
    'fpattern':
      "No pattern file found named: %s" % option,
    'startend':
      "The start of search must come before the end.",
    'openfile':
      "Failed opening file: %s" % option,
    'logwrite':
      "Could not write to the log file: %s" % option,
    'read':
      "Failed reading from file: %s" % option,
      
  }
  if err: sys.stderr.write(str(err) + "\n")
  sys.stderr.write("Error <" + str(code) + ">: " + error_codes[code] + "\n\n")
  sys.exit(128)


def get_args():
  """
  Parse all arguments from the command line using ArgumentParser.
  Returns an args object with attributes representing all arguments.
  """
  from argparse import ArgumentParser
  description = "An argument -f or -p is required. The -p argument accepts a hexidecimal pattern string and allows for missing characters, such as '0xFF??FF'. When using -f argument, the pattern file will be read as a binary file (not hex strings). If no search files are specified, %prog will read from standard input. The minimum memory required is about 3 times the size of the binary pattern. Increasing buffer-size will increase program search speed for large search files. All size arguments are read in decimal format, '-s 1024' = start searching after 1kilobyte. Reported finds are 0-based offset."
  p = ArgumentParser(description=description)
  
  def add(s, **kwargs):
    args = s.split(":")
    kwargs['dest'] = args.pop()
    kwargs['metavar'] = args.pop()
    kwargs['type'] = str if args.pop() else long ###
    p.add_argument(*args, **kwargs)
    
  add("-f:--file:string:FILE:fpattern",
      help = "file to read search pattern from")
  add("-p:--pattern:long:PATTERN:pattern",
      help = "a hexidecimal pattern in format '0xFF'")
  add("-b:--buffer-size:long:NUM:bsize",
      help = "read buffer size. 8MB default")
  add("-s:--start:long:NUM:start",
      help = "starting position in file to begin searching")
  add("-e:--end:long:NUM:end",
      help = "end search at this position, measuring from beginning of file")
  add("-m:--max-count:long:NUM:max",
      help = "maximum number of matches to find")
  add("-l:--log:string:FILE:log",
      help = "write matched offsets to FILE, instead of standard output")
  p.add_argument("fsearch", type=str, metavar = "FILE", nargs = "*",
                 help = "files to search in for the pattern")
  p.add_argument("-v", "--verbose", dest = "verbose", action = "store_true",
                 help = "verbose, output the number of bytes searched after each buffer read")
  p.add_argument("-V", "--version",  action = 'version', 
                 version = "%(prog)s " + VERSION)
  return p.parse_args()


# We will be keeping the parsed args object and editing its attributes!
def verify_args(ar):
  """
  Verify that all the parsed args are correct and work well together.
  Returns the modified args object.
  """
  # Make sure that exactly 1 pattern argument was given.
  if ar.fpattern and ar.pattern:
    _exit_error('2patterns')
  elif ar.fpattern is None and ar.pattern is None:
    _exit_error('0patterns')
  
  # Change ar.pattern into a list, and fill it with binary string pieces.
  if ar.fpattern:
    try: # If file specified, read it into memory.
      with open(ar.fpattern, 'r') as f:
        ar.pattern = [ f.read() ]
    except IOError, e:
      _exit_error('fpattern', ar.fpattern, e)
  else: # If not a file, split ar.patterns into searchable parts.
    if ar.pattern[:2] != "0x": # (Literal string searching may be included in future version)
      _exit_error('nohex')
    ar.pattern = ar.pattern[2:]
    try:
      ar.pattern = [ p.decode("hex") for p in ar.pattern.split("??") ]
    except TypeError, e:
      _exit_error('decode', ar.pattern, e)
  
  # Convert all number args from strings into long integers.
  try:
    for attr in [ "bsize", "max", "start", "end" ]:
      if getattr(ar, attr):
        setattr(ar, attr, long(getattr(ar, attr)))
  except ValueError, e:
    _exit_error('sizes', err=e)
  
  # Buffer size must be at least double max pattern size.
  if ar.bsize:
    if ar.bsize < len("?".join(ar.pattern)) * 2:
      _exit_error('bsize', len("?".join(ar.pattern)) * 2)
  else:
    ar.bsize = len("".join(ar.pattern)) * 2
    if ar.bsize < 2**23: # If bsize is < default, set to default.
      ar.bsize = 2**23
    
  # End must be after start? :)
  if ar.start and ar.end and ar.start >= ar.end:
    _exit_error('startend')
  
  # If log file is True, open it and replace ar.log with the file handler.
  if ar.log:
    try:
      ar.log = open(ar.log, "w")
    except IOError, e:
      _exit_error('openfile', ar.log, e)
  
  return ar


def search(ar, fh):
  """
  Searches the filehandler held by fh, with search settings in ar.
  Returns nothing when finished.
  """
  # Set start reading position in file.
  try:
    fh.seek(ar.start or 0)
  except IOError, e:
    _exit_error('read', fh.name, err=e)
  
  # Localize variables for increased speed.
  pattern = ar.pattern
  verbose = ar.verbose
  end = ar.end
  len_pattern = len("?".join(pattern))
  read_size = ar.bsize - len_pattern # Amount to read each loop.
  match = False
  find = 0
  
  try:
    sbuffer = fh.read(len_pattern)
    offset = long(ar.start or 0)
    while True: # Begin main loop.
      sbuffer += fh.read(read_size)
      # If sbuffer is empty, or exceeded end argument, finish loop.
      if len(sbuffer) <= len_pattern or (end and offset > end):
        return
      #print(len(sbuffer), "sbuffer") ## testing
      if verbose: # Print each loop offset if verbose is on.
        print("Passing offset: %14d %12X" % (offset, offset))
      find = sbuffer.find(pattern[0], find) # Search first pattern.
      #print(find) ##testing
      # While pattern is found and if find is less than read_size (we have enough buffer for pattern to fully fit within it (else loop and read more).
      while find != -1 and find < read_size:
        if end and offset + find > end: # Found out beyond end, finish search.
          return
        find += 1 # Increment find for next search.
        match = True # Set match True, but may be False if parts don't match.
        # If pattern has multiple parts, then attempt to match remaining parts of pattern to the buffer. If they do not match, set match to False.
        find2 = find + len(pattern[0]) # Use find2 for part matching loop.
        for part in pattern[1:]:
          #print(sbuffer[find2].encode("hex"), "hex sbuf") ## testing
          #print(part.encode("hex"), "part") ## testing
          if part and not sbuffer[find2:].startswith(part):
            match = False # If any part doesn't match, flag sets False.
            break
          find2 += len(part) + 1 # +1 for each empty string which was ??.
        #print(find, "find") ##testing
        if not match: # If no match, continue searching.
          find = sbuffer.find(pattern[0], find)
        # Else match is True, and all parts of pattern were found.
        else:
          if ar.max:
            ar.max -= 1
          find_offset = offset + find - 1
          s = "Match at offset: %14d %12X in  %s" % (
                      find_offset, find_offset, fh.name)
          if ar.log:
            try:
              ar.log.write(s + "\n")
            except IOError, e:
              _exit_error("logwrite", ar.log.name, e)
          else:
            print(s)
            if ar.max == 0:
              print("Found maximum number of matches.")
          if ar.max == 0:
            return
        find = sbuffer.find(pattern[0], find)
      else:
        if find == -1:
          find = read_size
      #print(len(sbuffer), find) ## testing
      
      offset += read_size # Increase offet by amount to read.
      sbuffer = sbuffer[read_size:] # Erase front portion of buffer.
      find = find - read_size # Shift find index for the shifted buffer.
      #print(len(sbuffer), find) ## testing
      assert find >= 0
  except IOError, e:
    _exit_error("read", fh.name, e)


def main():
  args = get_args() # Get commandline arguments.
  args = verify_args(args) # Check arguments for sanity, and edit them a bit.
  if args.fsearch: # If filenames were given on the commandline, process them.
    while args.fsearch: # List of files to search inside.
      try: # Open a filehandler for the filename.
        filehandler = open(args.fsearch[0], 'r')
      except IOError,e:
        _exit_error('openfile', args.fsearch[0], e)
      search(args, filehandler)
      args.fsearch.pop(0) # Remove each file after search.
  else: # If no files were given, search using stdin.
    search(args, sys.stdin)
  sys.exit(0)


if __name__ == "__main__":
  def exit(a, b):
    sys.exit()
  signal.signal(signal.SIGINT, exit)
  main()
