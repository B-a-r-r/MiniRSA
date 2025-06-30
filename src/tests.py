import unittest
from chiffrement import *
from utils import *
import _hashlib

class UtilsTests(unittest.TestCase):
    
    def test_int_to_ba(self):
        
        # Verify that the function returns a bytes object
        self.assertIsInstance(int_to_ba(1), bytes)
        
        # Verify that the returned bytes have a correct length
        x: int = ((145).bit_length() + 7) // 8
        self.assertEqual(len(int_to_ba(145)), x)
             
        # Verify that the function returns the correct bytes object
        self.assertEqual(int_to_ba(1), b'\x01')
        self.assertEqual(int_to_ba(256), b'\x01\x00')
        
    def test_ba_to_int(self):
        
        self.assertIsInstance(ba_to_int(b'\x01'), int)
        
        self.assertEqual(ba_to_int(b'\x01'), 1)
        self.assertEqual(ba_to_int(b'\x01\x00'), 256)
            
    def test_empreinte_message(self):
        
        self.assertIsInstance(empreinte_message(b'abc'), bytes)
        
        # The footprint is the hash of the message
        self.assertEqual(empreinte_message(b'abc'), hashlib.sha256(b'abc').digest())
        
    def test_verifier_integrite(self):
            
        self.assertIsInstance(verifier_integrite(b'abc', hashlib.sha256(b'abc').digest()), bool)
        
        # Verify that the obtained message is the same as the original message
        self.assertTrue(verifier_integrite(b'abc', hashlib.sha256(b'abc').digest()))
        self.assertFalse(verifier_integrite(b'abc', hashlib.sha256(b'abcd').digest()))

    def test_pad_bytes(self):
            
        self.assertIsInstance(pad_bytes(b'abc', 5), bytes)
        
        # Verify that the message is padded with the given
        # size - len(message) zeros.
        self.assertEqual(pad_bytes(b'abc', 3), b'abc')
        self.assertEqual(pad_bytes(b'abc', 5), b'abc\x00\x00')
            
    def test_decompose_message(self):

        # Verify that the function returns a tuple of the message and its footprint
        x = empreinte_message(b'abc')
        self.assertEqual(decompose_message(b'abc' + x), (b'abc', x))

class RsaTests(unittest.TestCase):
    
    def test_primalite(self):
        
        # Verify that the function that implements the Fermat test
        self.assertTrue(testPrimalite(2,3))
        self.assertTrue(testPrimalite(5,7))
        
        # Verify that the function that verifies if a number is prime and >11
        self.assertTrue(testPrimaliteTotal(73))
        self.assertFalse(testPrimaliteTotal(4))
        
    def test_create_key(self):
        
        # Verify that the function can't work with non prime numbers
        self.assertRaises(AssertionError, lambda: create_key(1, 6))
        self.assertRaises(AssertionError, lambda: create_key(4, 5))
        
        # Verify side effects of math.gcd
        self.assertEqual(math.gcd(3, 5), 1)
        
        # Verify that the function returns a dictionary with two keys
        res = create_key(3, 5)
        self.assertIsInstance(res, dict)
        self.assertEqual(len(res), 2)
        self.assertIn("pub", res)
        self.assertIn("pri", res)
        self.assertIsInstance(res["pub"], tuple)
        self.assertIsInstance(res["pri"], tuple)
    
    def test_chiffrement(self):
        
        # Verify side effects of pow
        self.assertEqual(pow(2, 3, 4), 0)
        
        # Verify that the function returns an integer
        self.assertIsInstance(chiffrement((3, 5), 2), int)
        
    def test_dechiffrement(self):
        
        key_pair = create_key(3, 5)
        
        self.assertIsInstance(dechiffrement(key_pair['pri'], 2), int)
        
        # Verify that the function returns the original message
        self.assertEqual(dechiffrement(key_pair['pri'], chiffrement(key_pair['pub'], 2)), 2)
        
    def tes_generationNombrePremier(self):
        
        self.assertIsInstance(generationNombrePremier(1, 6), int)
        
        # Verify that the function returns a prime number
        self.assertTrue(testPrimaliteTotal(generationNombrePremier(1, int(float("inf")))))
        
    def test_ChiffrageDechiffrageBytes(self):
            
            key_pair = create_key(generationNombrePremier(2**20, 2**21), generationNombrePremier(2**20, 2**21))
            
            # Verify that the function returns a bytes object
            res = ChiffrageBytes(key_pair['pub'], b'0000001')
            self.assertIsInstance(res, bytes)
            print(key_pair['pri'][1])
            print(key_pair['pri'][1].bit_length())
            self.assertIsInstance(DechiffrageBytes(key_pair['pri'], res), bytes)
            
            # Verify that the function returns the message decrypted
            self.assertEqual(DechiffrageBytes(key_pair['pri'], [2]), b'0000001')
       
        
if __name__ == '__main__':
    unittest.main()
    