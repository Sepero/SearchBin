#!/usr/bin/env python

"""
searchbin.py -t PATTERN [FILE [FILE...]]
searchbin.py -p PATTERN [FILE [FILE...]]
searchbin.py -f FILE [FILE [FILE...]]

examples:
./searchbin.py -t "hello" myfile.exe
Searches for the text "hello" in myfile.exe.

./searchbin.py -p "CCDDFF" myfile.exe
Searches for the hexidecimal pattern "CCDDFF" in myfile.exe.

./searchbin.py -f pattern.bin myfile.exe
Reads the file pattern.bin, and searches for a binary match within myfile.exe.

Many more capabilites, just run ./searchbin.py --help

+Features: no compiling, fast, small file, wild card matches, search multiple files of unlimited size, all operating systems
+Minimum Py2.7 required for argparse library
+keywords binary grep search seek find fast

license: BSD 2-Clause License, 2012, Sepero
license: http://www.opensource.org/licenses/BSD-2-Clause
"""

CONTACT=("sepero 111 @ gmail . com\n"
         "https://github.com/Sepero/SearchBin/issues/new\n"
         "http://seperohacker.blogspot.com/2012/04/binary-grep-program-searchbin.html")

VERSION="0.21"

import sys, signal, re

def _exit_error(code, option="", err=None):
  """
  Error information is kept here for the purposes of easier management and possibly language tranlation.
  Returns nothing.  All calls exit the program, error status 128.
  """
  error_codes = {
    "Xpatterns":
      "Cannot search for multiple patterns. '-t -p -f'",
    "0patterns":
      "No pattern to search for was supplied. '-t -p -f'",
    "decode":
      "The pattern string is invalid.\n" + str(option),
    "bsize":
      "The buffer size must be at least %s bytes." % str(option),
    "sizes":
      "Size parameters (-b -s -e -m) must be in decimal format.",
    "fpattern":
      "No pattern file found named: %s" % option,
    "startend":
      "The start of search must come before the end.",
    "openfile":
      "Failed opening file: %s" % option,
    "logwrite":
      "Could not write to the log file: %s" % option,
    "read":
      "Failed reading from file: %s" % option,
      
  }
  sys.stderr.write("version: %s\n" % VERSION)
  sys.stderr.write("Report issues to: %s\n" % CONTACT)
  if err: sys.stderr.write("%s\n" % str(err))
  sys.stderr.write("Error <%s>: %s\n\n" % (code, error_codes[code]))
  if __name__ == "__main__": sys.exit(128) # Exit under normal operation.


def get_args():
  """
  Parse all arguments from the command line using ArgumentParser.
  Returns an args object with attributes representing all arguments.
  """
  from argparse import ArgumentParser
  description = CONTACT +  """
  An argument -t or -p or -f is required. The -p argument accepts a 
  hexidecimal pattern string and allows for missing characters, 
  such as 'FF??FF'. When using -f argument, the pattern file will 
  be read as a binary file (not hex strings). If no search files are 
  specified, %prog will read from standard input. The minimum memory 
  required is about 3 times the size of the pattern byte length. 
  Increasing buffer-size will increase program search speed for 
  large search files. All size arguments (-b -s -e) are read in decimal 
  format, for example: '-s 1024' will start searching after 1kilobyte.
  Reported finds are 0-based offset.
  """
  p = ArgumentParser(description=description)
  
  def add(s, **kwargs):
    args = s.split(":")
    
    value = args.pop() # pop last item.
    if value:
      kwargs["dest"] = value
    value = args.pop()
    if value:
      kwargs["metavar"] = value
    value = args.pop()
    if value:
      kwargs["type"] = eval(value) #(type)(value) # str(value) or long(value).
    
    p.add_argument(*args, **kwargs)
  
  add("-f:--file:str:FILE:fpattern",
      help = "file to read search pattern from")
  add("-t:--text:str:PATTERN:tpattern",
      help = "a (non-unicode case-sensitive) text string to search for")
  add("-p:--pattern:str:PATTERN:ppattern",
      help = "a hexidecimal pattern to search for")
  add("-b:--buffer-size:long:NUM:bsize",
      help = "read buffer size (in bytes). 8MB default")
  add("-s:--start:long:NUM:start",
      help = "starting position in file to begin searching, as bytes")
  add("-e:--end:long:NUM:end",
      help = "end search at this position, measuring from beginning of file")
  add("-m:--max-matches:long:NUM:max_matches",
      help = "maximum number of matches to find (0=infinite)")
  add("-l:--log:str:FILE:log",
      help = "write matched offsets to FILE, instead of standard output")
  add("str:FILE:fsearch", nargs = "*",
      help = "files to search within")
  add("-v:--verbose:::verbose", action = "store_true",
      help = "verbose, output the number of bytes searched after each buffer read")
  add("-V:--version:::", action = "version",
      version = "%(prog)s " + VERSION)
  add("-d:--debug:::debug", action = "store_true",
      help = "debugging (don't use this)")
      
  return p.parse_args()


def hex_to_pattern(hex):
  ret = []
  pattern = hex
  if hex[:2] == "0x": # Remove "0x" from start if it exists.
    pattern = hex[2:]
  try:
    ret = [ p for p in pattern.split("??") ]
    return [ p.decode("hex") for p in ret ]
  except TypeError, e:
    _exit_error("decode", hex, e)


def text_to_pattern(text):
  return [ t for t in text.split("?") ]


def file_to_pattern(fname):
  try: # If file specified, read it into memory.
    with open(fname, "r") as f:
      return [f.read()]
  except IOError, e:
    _exit_error("fpattern", fname, e)


# We will be keeping the parsed args object and editing its attributes!
def verify_args(ar):
  """
  Verify that all the parsed args are correct and work well together.
  Returns the modified args object.
  """
  # Make sure that exactly 1 pattern argument was given.
  all_patterns = filter(None, [ar.fpattern, ar.ppattern, ar.tpattern])
  if len(all_patterns) > 1:
    _exit_error("Xpatterns")
  if len(all_patterns) == 0:
    _exit_error("0patterns")
  
  # Create a new variable ar.pattern, and fill it with
  # whichever pattern we have -t -f -p. ar.pattern will be a list.
  if ar.fpattern:
    ar.pattern = file_to_pattern(ar.fpattern)
  elif ar.tpattern:
    ar.pattern = text_to_pattern(ar.tpattern)
  else:
    ar.pattern = hex_to_pattern(ar.ppattern)
  
  # Convert all number args from strings into long integers.
  try:
    for attr in [ "bsize", "max_matches", "start", "end" ]:
      if getattr(ar, attr):
        setattr(ar, attr, long(getattr(ar, attr)))
  except ValueError, e:
    _exit_error("sizes", err=e)
  
  # Buffer size must be at least double maximum pattern size.
  if ar.bsize:
    if ar.bsize < len("?".join(ar.pattern)) * 2:
      _exit_error("bsize", len("?".join(ar.pattern)) * 2)
  else:
    ar.bsize = len("".join(ar.pattern)) * 2
    ar.bsize = max(ar.bsize, 2**23) # If bsize is < default, set to default.
  
  # End must be after start  :)
  if ar.start and ar.end and ar.start >= ar.end:
    _exit_error("startend")
  
  # If log file is True, open it and replace ar.log with the file handler.
  if ar.log:
    try:
      ar.log = open(ar.log, "w")
    except IOError, e:
      _exit_error("openfile", ar.log, e)
  
  return ar


def search(ar, fh, debug=False):
  """
  This function is simply a wrapper to forward needed variables in a way
  to make them all local variables. Local variables are faster than
  accessing object attribute variables.
  Returns nothing.
  """
  if not ar.debug:
    _search_loop(ar.start, ar.end, ar.bsize, ar.pattern,
                 ar.max_matches, ar.log, ar.verbose, fh.name,
                 fh.read, fh.seek)
  else:
    _debug_search(ar.pattern, fh.name, fh.read)


def _debug_search(pattern, fh_name, fh_read):
  """
  Slower, less functional, but less error prone search.
  For debugging purposes.
  Returns nothing.
  """
  len_pattern = len("?".join(pattern))
  read_size = 2**24 - len_pattern # Amount to read each loop.
  pattern = [ re.escape(p) for p in pattern ]
  pattern = ".".join(pattern)
  regex = re.compile(pattern, re.DOTALL+re.MULTILINE)
  
  try:
    sbuffer = fh_read(len_pattern + read_size)
    offset = 0
    match = regex.search(sbuffer)
    while True:
      if not match:
        offset += read_size
        sbuffer = sbuffer[read_size:] # Erase front portion of buffer.
        sbuffer += fh_read(read_size)
        match = regex.search(sbuffer)
      else:
        print "Match at offset: %14d %12X in  %s" % (
                      offset+match.start(), offset+match.start(), fh_name)
        match = regex.search(sbuffer, match.start()+1)
        
      if len(sbuffer) <= len_pattern:
        return
  except IOError, e:
    _exit_error("read", fh_name, e)


def _search_loop(start, end, bsize, pattern, max_matches,
                  log, verbose, fh_name, fh_read, fh_seek):
  """
  Searches the filehandler held by fh, with search settings in ar.
  Returns nothing.
  """
  len_pattern = len("?".join(pattern)) # Byte length of pattern.
  read_size = bsize - len_pattern # Amount to read each loop.
  
  # Convert pattern into a regular expression for insane fast searching.
  pattern = [ re.escape(p) for p in pattern ]
  pattern = ".".join(pattern)
  # Grab regex search function directly to speed up function calls.
  regex_search = re.compile(pattern, re.DOTALL+re.MULTILINE).search
  
  # Set start reading position in file.
  try:
    fh_seek(start or 0)
  except IOError, e:
    _exit_error("read", fh_name, err=e)
  
  try:
    offset = long(start or 0)
    sbuffer = fh_read(len_pattern + read_size)
    match = regex_search(sbuffer)
    match = -1 if match == None else match.start()
    while True:
      if match == -1:
        offset += read_size
        # If end exists and we are beyond end, finish search.
        if end and offset > end:
          return
        sbuffer = sbuffer[read_size:] # Erase front portion of buffer.
        sbuffer += fh_read(read_size)
        match = regex_search(sbuffer)
        # If there is no match set match to -1, else the matching position.
        match = -1 if match == None else match.start()
        if verbose: # Print each loop offset if verbose is on.
          print("Passing offset: %14d %12X" % (offset, offset))
      else:
        # If end exists and we are beyond end, finish search.
        if match == -1 and offset + match > end:
          return
        
        # Print matched offset.
        find_offset = offset + match
        print "Match at offset: %14d %12X in  %s" % (
                      find_offset, find_offset, fh_name)
        
        if max_matches:
          max_matches -= 1
          if max_matches == 0: # If maximum matches are found, then end.
            print("Found maximum number of matches.")
            return
        
        # Get next match.
        match = regex_search(sbuffer, match+1)
        match = -1 if match == None else match.start()
        
      if len(sbuffer) <= len_pattern: # Finished reading file- end.
        return
  except IOError, e:
    _exit_error("read", fh_name, e)


def main():
  args = get_args() # Get commandline arguments.
  args = verify_args(args) # Check arguments for sanity, and edit them a bit.
  if args.fsearch: # If filenames were given on the commandline, process them.
    while args.fsearch: # List of files to search inside.
      try: # Open a filehandler for the filename.
        filehandler = open(args.fsearch[0], "r")
      except IOError,e:
        _exit_error("openfile", args.fsearch[0], e)
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

