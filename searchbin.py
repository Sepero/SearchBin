#!/usr/bin/env python
"""
searchbin.py -t PATTERN [FILE [FILE...]]
searchbin.py -p PATTERN [FILE [FILE...]]
searchbin.py -f FILE    [FILE [FILE...]]

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

from __future__ import unicode_literals
import re
import signal
import sys

# Global variables.
CONTACT=("sepero 111 @ gmx . com\n"
		"https://bitbucket.org/Sepero/searchbin/issues/new\n"
		"http://seperohacker.blogspot.com/2012/04/binary-grep-program-searchbin.html")

VERSION="1.00"
DEBUG = False
STDOUT = sys.stdout

try:    # Python 3 modifications.
	STDIN = sys.stdin.buffer
except: # Python 2 modifications.
	STDIN = sys.stdin
	range = xrange


def _exit_error(code, option="", err=None):
	"""
	Error information is kept here for the purposes of easier management and possibly language tranlation.
	Returns nothing. All calls exit the program, error status 128.
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
	
	import traceback
	sys.stderr.write(traceback.format_exc() + "\n")
	if not DEBUG:
		sys.stderr.write("version: %s\n" % VERSION)
		sys.stderr.write("Please Report issues to: %s\n" % CONTACT)
		if err: sys.stderr.write("%s\n" % str(err))
	sys.stderr.write("Error <%s>: %s\n\n" % (code, error_codes[code]))
	if __name__ == "__main__": sys.exit(128) # Exit under normal operation.


def get_args():
	"""
	Parse all arguments from the command line using ArgumentParser.
	Returns an args object with attributes representing all arguments.
	"""
	from argparse import ArgumentParser
	description = CONTACT + """
	An argument -t or -p or -f is required. The -p argument accepts a 
	hexidecimal pattern string and allows for missing characters, 
	such as 'FF??FF'. When using -f argument, the pattern file will 
	be read as a binary file (not hex strings). If no search files are 
	specified, %prog will read from standard input. The minimum memory 
	required is about 3 times the size of the pattern byte length. 
	Increasing buffer-size will increase program search speed for 
	large search files. All size arguments (-b -s -e) are read in decimal 
	format, for example: '-s 1024' will start searching after 1kilobyte.
	format, for example: '-s 1024' will start searching after 1kilobyte.
	Reported finds are 0-based offset.
	"""
	p = ArgumentParser(description=description)
	
	def add(s, **kwargs):
		args = s.split(':')
		
		value = args.pop(2) # Pop item at index 2 (argument type).
		if value: kwargs['type'] = eval(value) #(type)(value) # str(value) or long(value).
		value = args.pop(2) # Pop item at index 2 (argument metavar).
		if value: kwargs['metavar'] = value
		value = args.pop(2) # Pop item at index 2 (argument name/destination).
		if value: kwargs['dest'] = value
		
		p.add_argument(*args, **kwargs)
	
	p.add_argument('-f', '--file', type=str,
			metavar='FILE', dest='fpattern',
			help='file to read search pattern from')
	p.add_argument('-t', '--text', type=str,
			metavar='PATTERN', dest='tpattern',
			help='a (utf-8 case-sensitive) text string to search for')
	p.add_argument('-p', '--pattern', type=str, # I would use -h for hex, but that's used for help output.
			metavar='PATTERN', dest='ppattern',
			help='a hexidecimal pattern to search for')
	try:    # Python 3.
		p.add_argument('-b', '--buffer-size', type=int,
				metavar='NUM', dest='bsize',
				help='read buffer size (in bytes). 8MB default')
		p.add_argument('-s', '--start', type=int,
				metavar='NUM', dest='start',
				help='starting position in file to begin searching, as bytes')
		p.add_argument('-e', '--end', type=int,
				metavar='NUM', dest='end',
				help='end search at this position, measuring from beginning of file')
		p.add_argument('-m', '--max-matches', type=int,
				metavar='NUM', dest='max_matches',
				help='maximum number of matches to find (0=infinite)')
	except: # Python 2.
		p.add_argument('-b', '--buffer-size', type=long,
				metavar='NUM', dest='bsize',
				help='read buffer size (in bytes). 8MB default')
		p.add_argument('-s', '--start', type=long,
				metavar='NUM', dest='start',
				help='starting position in file to begin searching, as bytes')
		p.add_argument('-e', '--end', type=long,
				metavar='NUM', dest='end',
				help='end search at this position, measuring from beginning of file')
		p.add_argument('-m', '--max-matches', type=long,
				metavar='NUM', dest='max_matches',
				help='maximum number of matches to find (0=infinite)')
	p.add_argument('-l', '--log', type=str,
			metavar='FILE', dest='log',
			help='write matched offsets to FILE, instead of standard output')
	p.add_argument(type=str,
			metavar='FILE', dest='fsearch', nargs='*',
			help='files to search within')
	p.add_argument('-v', '--verbose',
			dest='verbose', action='store_true',
			help='verbose, output the number of bytes searched after each buffer read')
	p.add_argument('-V', '--version',
			action='version', version='%(prog)s ' + VERSION)
	p.add_argument('-d', '--debug',
			dest='debug', action='store_true',
			help='debugging (don\'t use this)')
	
	return p.parse_args()


"""
=Patterns=
A pattern is a list. It represents the division between known and unknown
bytes to search for. All hex/text/file input is converted to a pattern.
Examples of conversions:
hex "31??33" becomes ['A', 'C']  # Everything is converted internally to strings, even though they may not be printable characters.
text "A?C"   becomes ['A', 'C']
text "A??C"  becomes ['A', '', 'C']
"""
def hex_to_pattern(hex):
	""" Converts a hex string into a pattern. """
	ret = []
	pattern = hex
	if hex[:2] == "0x": # Remove "0x" from start if it exists.
		pattern = hex[2:]
	try:
		ret = [ p for p in pattern.split("??") ]
		try:                  # Python 3.
			return [ bytes.fromhex(p) for p in ret ]
		except AttributeError: # Python 2.
			return [ p.decode("hex") for p in ret ]
	#except :
		#e = sys.exc_info()[1]
		#_exit_error("decode", hex, e)
	except(TypeError, ValueError):
		e = sys.exc_info()[1]
		_exit_error("decode", hex, e)


def text_to_pattern(text):
	""" Converts a text string into a pattern. """
	try:              # Python 3.
		return [ t.encode('utf-8') for t in text.split("?") ]
	except TypeError: # Python 2.
		return [ t for t in text.split("?") ]


def file_to_pattern(fname):
	""" Converts a file into a pattern. """
	try: # If file specified, read it into memory.
		with open(fname, "rb") as f:
			return [f.read()]
	except IOError:
		e = sys.exc_info()[1]
		_exit_error("fpattern", fname, e)


# We will be keeping the parsed args object and editing its attributes!
def verify_args(ar):
	"""
	Verify that all the parsed args are correct and work well together.
	Returns the modified args object.
	"""
	DEBUG = ar.debug
	
	# Make sure that exactly 1 pattern argument was given.
	all_patterns = list(filter(None, [ar.fpattern, ar.ppattern, ar.tpattern]))
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
	except ValueError:
		e = sys.exc_info()[1]
		_exit_error("sizes", err=e)
	
	# Buffer size must be at least double maximum pattern size.
	if ar.bsize:
		if ar.bsize < len("?".join(ar.pattern)) * 2:
			_exit_error("bsize", len("?".join(ar.pattern)) * 2)
	else:
		ar.bsize = len(b"".join(ar.pattern)) * 2
		ar.bsize = max(ar.bsize, 2**23) # If bsize is < default, set to default.
	
	# Set start and end values to 0 if not set.
	ar.start =  ar.start or 0
	ar.end = ar.end or 0
	# End must be after start.  :)
	if ar.start and ar.start >= ar.end:
		_exit_error("startend")
	
	# If log file is True, open it and replace ar.log with the file handler.
	if ar.log:
		try:
			ar.log = open(ar.log, "w")
		except IOError:
			e = sys.exc_info()[1]
			_exit_error("openfile", ar.log, e)
	
	return ar


def search(ar, fh):
	"""
	This function is simply a wrapper to forward needed variables in a way
	to make them all local variables. Accessing local variables is faster than
	accessing object.attribute variables.
	Returns nothing.
	"""
	if not DEBUG:
		_search_loop(ar.start, ar.end, ar.bsize, ar.pattern,
				ar.max_matches, ar.log, ar.verbose, fh.name,
				fh.read, fh.seek)
	else:
		_debug_search(ar.pattern, fh.name, fh.read)


def _debug_search(pattern, fh_name, fh_read):
	"""
	Slower, less functional, but less error prone simple search.
	For debugging purposes.
	Returns nothing.
	"""
	len_pattern = len(b"?".join(pattern))
	read_size = 2**24 - len_pattern # Amount to read each loop.
	pattern = [ re.escape(p) for p in pattern ]
	pattern = b".".join(pattern)
	regex = re.compile(pattern, re.DOTALL+re.MULTILINE)
	
	try:
		buffer = fh_read(len_pattern + read_size)
		offset = 0
		match = regex.search(buffer)
		while True:
			if not match:
				offset += read_size
				buffer = buffer[read_size:] # Erase front portion of buffer.
				buffer += fh_read(read_size)
				match = regex.search(buffer)
			else:
				STDOUT.write("Match at offset: %14d %12X in  %s\n" % (
						offset+match.start(), offset+match.start(), fh_name))
				match = regex.search(buffer, match.start()+1)
			
			if len(buffer) <= len_pattern:
				return
	except IOError:
		e = sys.exc_info()[1]
		_exit_error("read", fh_name, e)


def _search_loop(start, end, bsize, pattern, max_matches,
		log, verbose, fh_name, fh_read, fh_seek):
	"""
	Primary search function.
	Returns nothing.
	"""
	len_pattern = len(b"?".join(pattern)) # Byte length of pattern.
	read_size = bsize - len_pattern # Amount to read each loop.
	
	# Convert pattern into a regular expression for insane fast searching.
	pattern = [ re.escape(p) for p in pattern ]
	pattern = b".".join(pattern)
	# Grab regex search function directly to speed up function calls.
	regex_search = re.compile(pattern, re.DOTALL+re.MULTILINE).search
	
	offset = start or 0
	# Set start reading position in file.
	try:
		if offset:
			fh_seek(offset)
	except IOError:
		e = sys.exc_info()[1]
		_exit_error("read", fh_name, err=e)
	
	try:
		buffer = fh_read(len_pattern + read_size) # Get initial buffer amount.
		match = regex_search(buffer) # Search for a match in the buffer.
		# Set match to -1 if no match, else set it to the match position.
		match = -1 if match == None else match.start()
		
		while True: # Begin main loop for searching through a file.
			if match == -1: # No match.
				offset += read_size
				# If end exists and we are beyond end, finish search.
				if end and offset > end:
					return
				buffer = buffer[read_size:] # Erase front portion of buffer.
				buffer += fh_read(read_size) # Read more into the buffer.
				match = regex_search(buffer) # Search for next match in the buffer.
				# If there is no match set match to -1, else the matching position.
				match = -1 if match == None else match.start()
				if verbose: # Print each loop offset if verbose is on.
					STDOUT.write("Passing offset: %14d %12X\n" % (offset, offset))
			else: # Else- there was a match.
				# If end exists and we are beyond end, finish search.
				if match == -1 and offset + match > end:
					return
				
				# Print matched offset.
				find_offset = offset + match
				STDOUT.write("Match at offset: %14d %12X in  %s\n" % (
						find_offset, find_offset, fh_name))
				
				if max_matches:
					max_matches -= 1
					if max_matches == 0: # If maximum matches are found, then end.
						STDOUT.write("Found maximum number of matches.\n")
						return
				
				# Search for next match in the buffer.
				match = regex_search(buffer, match+1)
				match = -1 if match == None else match.start()
				
			if len(buffer) <= len_pattern: # If finished reading input then end.
				return
				
		# Main loop closes here.
	
	except IOError:
		e = sys.exc_info()[1]
		_exit_error("read", fh_name, e)


def main():
	args = get_args() # Get commandline arguments.
	args = verify_args(args) # Check arguments for sanity, and edit them a bit.
	if args.fsearch: # If filenames were given on the commandline, process them.
		while args.fsearch: # List of files to search inside.
			try: # Open a filehandler for the filename.
				filehandler = open(args.fsearch[0], "rb")
			except IOError:
				e = sys.exc_info()[1]
				_exit_error("openfile", args.fsearch[0], e)
			search(args, filehandler)
			filehandler.close()
			args.fsearch.pop(0) # Remove each file after search.
	else: # If no files were given, search using stdin.
		
		search(args, STDIN)
	sys.exit(0)


if __name__ == "__main__":
	# This allows the program to exit quickly when pressing ctrl+c.
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	
	main()
