"""
Discord File System
Copyright (C) 2022  NWhut

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class AESCipher(object):

	def __init__(self, key): 
		self.bs = AES.block_size
		self.key = hashlib.sha256(key.encode()).digest()

	def encrypt(self, raw):
		raw = pad(raw.encode(), self.bs)
		cipher = AES.new(self.key, AES.MODE_ECB)
		return base64.b64encode(cipher.encrypt(raw))

	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		cipher = AES.new(self.key, AES.MODE_ECB)
		return unpad(cipher.decrypt(enc), self.bs).decode()
