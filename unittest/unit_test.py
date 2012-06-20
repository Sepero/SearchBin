#!/usr/bin/env python

import unittest, os, sys, random
sys.path.append("..")
import searchbin as s

class MyTest(unittest.TestCase):
  def __init__(self):
    super.__init__(self)
    self.randoms = []
    for i in xrange(1000):
      num = random.randint(0, 1000000000)
      self.randoms.append("%X" % num)
  
  def setUp(self):
    random.seed()
  
  def test_hex(self):
    for i in xrange(1000):
      num = random.randint(0, 1000000000)
      str1 = "%X" % num
      if len(str1)%2 != 0:
        str1 = "0" + str1
      str2 = "0x" + str1
      self.assertEqual(s.hex_to_pattern(str1)[0], str1.decode("hex"))
      self.assertEqual(s.hex_to_pattern(str2)[0], str1.decode("hex"))
      
      r = random.randint(0, 5) * 2
      if len(str1) > r:
        str1 = str1[:r] + "??" + str1[r:]
      
      self.assertTrue(s.hex_to_pattern(str1))
      
      try:
        s.hex_to_pattern(str(random.randint(0,1000000)).decode("hex")+str2)
        self.assertFalse(True) # This statement should never be reached.
      except:
        pass
  
  def test_text(self):
    pass
  
  def tearDown(self):
    pass


if __name__ == '__main__':
  unittest.main()

