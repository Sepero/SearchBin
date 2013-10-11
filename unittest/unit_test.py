#!/usr/bin/env python
from __future__ import print_function
from __future__ import unicode_literals

import os
import random
import sys
import unittest
sys.path.append("..")
import searchbin
from io import BytesIO, StringIO
try:    # Python 3 imports.
	range = xrange
except: # Python 2 imports.
	pass


def get_rand_hex_str():
	""" Generate and return a random hex number as a string. """
	# Generate a random number.
	num = random.randint(0, 1000000000)
	
	# Turn number into a hex string.
	hex_str = "%X" % num
	
	# Make sure hex string is an even number of characters long."
	if len(hex_str)%2 != 0:
		hex_str = "0" + hex_str
	
	return hex_str


class MyTest(unittest.TestCase):
	def run_search(self, searchbin, arguments, fh):
		""" Searches for arguments.pattern within the file (fh). Returns any output. """
		# Change the STDOUT so we can capture and return it.
		searchbin.STDOUT = StringIO()
		
		# Reset the file position for searching.
		fh.seek(arguments.start)
		
		if searchbin.DEBUG:
			print("debug")
		print("Searching", arguments.pattern)
		
		# Runs search using searchbin.
		searchbin.search(arguments, fh)
		
		return searchbin.STDOUT.getvalue()
	
	
	def setUp(self):
		random.seed()
		#self.randoms = []
		#for i in range(1000):
			#num = random.randint(0, 1000000000)
			#self.randoms.append("%X" % num)
	
	
	def test_bad_hex(self):
		# Send bad hex to function.
		try:
			searchbin.hex_to_pattern("AAGG")
			self.assertFalse(True) # This statement should never be reached.
		except:
			pass
		
		try:
			s1 = str('{:x}'.format(random.randint(0,1000000))).zfill(6)
			s2 = str('{:x}'.format(random.randint(0,1000000))).zfill(6)
			# It attempts to send a hex string with "0x" in the middle.
			searchbin.hex_to_pattern(s1+"0x"+s2)
			self.assertFalse(True) # This statement should never be reached.
		except(TypeError, ValueError):
			pass
	
	
	def test_hex(self):
		"""Test the hex_to_pattern() function"""
		
		for i in range(1000):
			hex_str1 = get_rand_hex_str()
			
			# Second hex starting with "0x". It should pass same tests.
			hex_str2 = "0x" + hex_str1
			
			# Make sure hex string encodes to pattern and decodes to same hex string.
			try:               # Python 3.
				self.assertEqual(searchbin.hex_to_pattern(hex_str1)[0], bytes.fromhex(hex_str1))
				self.assertEqual(searchbin.hex_to_pattern(hex_str2)[0], bytes.fromhex(hex_str1))
			except AttributeError: # Python 2.
				self.assertEqual(searchbin.hex_to_pattern(hex_str1)[0], hex_str1.decode("hex"))
				self.assertEqual(searchbin.hex_to_pattern(hex_str2)[0], hex_str1.decode("hex"))
			
			# Insert a couple "??" at random places in the hex string.
			for i in range(2):
				r = random.randint(0, 10) * 2
				if len(hex_str1) > r:
					hex_str1 = hex_str1[:r] + "??" + hex_str1[r:]
			
			# Make sure the pattern can match the random number.
			self.assertTrue(searchbin.hex_to_pattern(hex_str1))
			
			try:
				# Make sure this fails. It attempts to send a hex string with "0x" in the middle.
				try:               # Python 3.
					searchbin.hex_to_pattern(str(random.randint(0,1000000)).decode("hex")+hex_str2)
					self.assertFalse(True) # This statement should never be reached.
				except ImportError: # Python 2.
					searchbin.hex_to_pattern(str(random.randint(0,1000000)).decode("hex")+hex_str2)
					self.assertFalse(True) # This statement should never be reached.
			except:
				pass
	
	
	def test_search(self):
		# Generate a large sample of data for testing.
		data = 0
		for i in range(2000):
			data += i
			data *= i
		
		# Convert integer data into bytes.
		s1 = '{:x}'.format(data)
		try:    # Python 3.
			s2 = bytes.fromhex(s1)
		except: # Python 2.
			s2 = s1.decode('hex')
		fh = BytesIO(s2)
		fh.name = 'null'
		
		# Create program arguments for running search.
		class MyDynamicClass(object): pass
		arguments = MyDynamicClass()
		arguments.start = 0
		arguments.end = 0
		arguments.bsize = 2**23
		arguments.max_matches = 0
		arguments.log = False
		arguments.verbose = False
		
		# Run tests twice, with and without debug mode.
		searchbin.DEBUG = True
		for i in range(2):
			arguments.pattern = [ b'9wiC' ]
			output = self.run_search(searchbin, arguments, fh)
			assert(output == "Match at offset:           1890          762 in  null\n")
			
			arguments.pattern = [ b'Nfg', b'wiC', b'', b'J', b'-', b'', b'H', b']' ]
			output = self.run_search(searchbin, arguments, fh)
			assert(output == "Match at offset:           1887          75F in  null\n")
			
			arguments.pattern = [ b'NfgwiC' ]
			output = self.run_search(searchbin, arguments, fh)
			assert(output == '')
			
			searchbin.DEBUG = False


	def tearDown(self):
		pass
	


if __name__ == '__main__':
	unittest.main() #import ipdb; ipdb.set_trace()
	

