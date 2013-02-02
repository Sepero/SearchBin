#!/usr/bin/env python

import unittest, os, sys, random
sys.path.append("..")
import searchbin as s

class MyTest(unittest.TestCase):
	def setUp(self):
		random.seed()
		#self.randoms = []
		#for i in xrange(1000):
			#num = random.randint(0, 1000000000)
			#self.randoms.append("%X" % num)
	
	def test_hex(self):
		"""Test the hex_to_pattern() function"""
		for i in xrange(1000):
			num = random.randint(0, 1000000000)
			# Turn random number into a hex string.
			hex_str1 = "%X" % num
			
			# Make sure the random hex string is an even number of characters long."
			if len(hex_str1)%2 != 0:
				hex_str1 = "0" + hex_str1
			
			# Test against plain hex, and hex starting with "0x".
			hex_str2 = "0x" + hex_str1
			
			self.assertEqual(s.hex_to_pattern(hex_str1)[0], hex_str1.decode("hex"))
			self.assertEqual(s.hex_to_pattern(hex_str2)[0], hex_str1.decode("hex"))
			
			# Create a random pattern with a few "??" in it.
			r = random.randint(0, 5) * 2
			if len(hex_str1) > r:
				hex_str1 = hex_str1[:r] + "??" + hex_str1[r:]
			
			# Make sure the pattern can match the random number.
			self.assertTrue(s.hex_to_pattern(hex_str1))
			
			try:
				# Make sure this fails on error.
				s.hex_to_pattern(str(random.randint(0,1000000)).decode("hex")+hex_str2)
				self.assertFalse(True) # This statement should never be reached.
			except:
				pass
	
	def test_text(self):
		pass
	
	def tearDown(self):
		pass


if __name__ == '__main__':
	unittest.main() #import ipdb; ipdb.set_trace()
	
