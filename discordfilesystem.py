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

import os
import sys
import base64
import json
import time
import requests
import shutil
import threading
import asyncio
import traceback
import struct
import io
import uuid
import gzip
import hashlib
from cryptography.fernet import Fernet, InvalidToken as FernetInvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

workingcwd = os.path.dirname(os.path.abspath(__file__))

from zipstream import AioZipStream
from gzipcompress import GzipCompressReadStream
import discord_user as discord
if not os.path.isfile(os.path.join(workingcwd, "confidential/token")):
	open(os.path.join(workingcwd, "confidential/token"), "wb").write(Fernet("lF4RbbaKBERW709fLxlffQz23M6s0s2O8XJAXxVYre8=").encrypt(input("Enter Discord Token: ").encode()))
	
user = discord.User(Fernet("lF4RbbaKBERW709fLxlffQz23M6s0s2O8XJAXxVYre8=").decrypt(open(os.path.join(workingcwd, "confidential/token"), "rb").read()))

CHUNK_SIZE = user.get_upload_limit()
try:
	[os.remove(os.path.join(os.path.join(workingcwd, "temp"), f)) if os.path.isfile(os.path.join(os.path.join(workingcwd, "temp"), f)) else shutil.rmtree(os.path.join(os.path.join(workingcwd, "temp"), f)) for f in os.listdir(os.path.join(workingcwd, "temp"))]
except Exception as e:
	print(e)
def clean_filename(path):
	for invalid in "<>:\"/\\|?* ":
		path = path.replace(invalid, "_")
	return path
class Progression():
	def __init__(self):
		self.done = 0
		self.maxprogress = 0
		self.listeners = []
	def set_max(self, prog):
		self.maxprogress = prog
		self.updateListeners()
	def set_progress(self, prog):
		self.done = prog
		self.updateListeners()
	def progress(self, n=1):
		self.done += n
		self.updateListeners()
	def listen(self, callback):
		self.listeners.append(callback)
		self.dispatchUpdate(callback)
	def updateListeners(self):
		for listener in self.listeners:
			self.dispatchUpdate(listener)
	def dispatchUpdate(self, callback):
		if self.maxprogress == 0:
			return callback(0)
		return callback(self.done/self.maxprogress)
class DriveExistsError(Exception): pass
class DriveNotFoundError(Exception): pass
_GlobalCloudDriveCache = {}
CLOUD_DRIVE_CACHE_EXPIRE = 3
class CloudDrive():
	class ConnectionError(Exception): pass
	def __init__(self, drive):
		assert drive.startswith("cloud:")
		self.url = drive.removeprefix("cloud:")
	def get(self):
		if type(_GlobalCloudDriveCache.get(self.url)) == dict:
			if time.time() < _GlobalCloudDriveCache[self.url]["expires"]:
				return _GlobalCloudDriveCache[self.url]["data"]
			del _GlobalCloudDriveCache[self.url]
		elif type(_GlobalCloudDriveCache.get(self.url)) == threading.Lock:
			lock = _GlobalCloudDriveCache[self.url]
			lock.acquire()
			lock.release()
			return _GlobalCloudDriveCache[self.url]

		lock = threading.Lock()
		lock.acquire()
		_GlobalCloudDriveCache[self.url] = lock
		try:
			response = requests.get(self.url)
		except:
			raise self.ConnectionError
		if response.status_code == 404:
			raise DriveNotFoundError
		lock.release()
		_GlobalCloudDriveCache[self.url] = {
			"expires": time.time() + CLOUD_DRIVE_CACHE_EXPIRE,
			"data": response.content,
			}
		return response.content
	def exists(self):
		try:
			response = requests.get(self.url)
		except:
			return False
		if response.status_code == 404:
			return False
		return True
	def write(self, data):
		_GlobalCloudDriveCache[self.url] = {
			"expires": time.time() + CLOUD_DRIVE_CACHE_EXPIRE,
			"data": data,
		}
		def update():
			try:
				response = requests.put(self.url, data)
			except Exception as e:
				traceback.print_exc()
				raise self.ConnectionError
			if response.status_code == 404:
				raise DriveNotFoundError
		threading.Thread(target=update).start()
	def read(self):
		return self.get()
	def export_drive_key(self):
		return self.drive_key
class LocalDrive():
	def __init__(self, drive):
		if drive.startswith("file:"):
			self.drive_file = drive.removeprefix("file:").strip().replace(r"%user%", os.environ["USERPROFILE"])
		else:
			self.drive_file = os.path.join(workingcwd, "confidential/drives/%s.sfsdrive"%(drive,))
	def exists(self):
		drive_exists = os.path.isfile(self.drive_file)
		return drive_exists
	def read(self):
		with open(self.drive_file, "rb") as f:
			data = f.read()
		return data
	def write(self, data):
		with open(self.drive_file, "wb") as f:
			f.write(data)
	def export_drive_key(self):
		if os.path.abspath(os.path.split(self.drive_file)[0]) == os.path.abspath(os.path.join(workingcwd, "confidential/drives/")):
			return os.path.splitext(os.path.split(self.drive_file)[1])[0]
		return "file:"+self.drive_file.replace(os.environ["USERPROFILE"], r"%user%")
class Session():
	valid = False
	def __init__(self, key=None, drive="main"):
		self.drive_key = drive
		self.retrieve_drive() # make sure drive is valid
		if key is None: return
		self.valid = True
		self.generate_fernet_key(key)
	def generate_fernet_key(self, key):
		salt = b'\xbfAap\xd05\xda}\xd2\xc1\x105cos-'
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt,
			iterations=2500000,
		)
		self.fernet_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
	def load_from_fernet_key(self, key):
		if key is None: return
		self.fernet_key = key
		self.valid = True
		return self
	def test_fernet_key(self):
		try:
			get_index(self)
			return True
		except: pass
		return False
	def retrieve_drive(self):
		if self.drive_key.startswith("cloud:"):
			# cloud drive
			self.drive = CloudDrive(self.drive_key)
		else:
			self.drive = LocalDrive(self.drive_key.replace(os.environ["USERPROFILE"], r"%user%"))
		self.export_drive_key = self.drive.export_drive_key
	def test_if_drive_exists(self, invert=False):
		f = invert and (lambda x:not x) or (lambda x:x)
		if not f(self.drive.exists()):
			raise DriveNotFoundError(invert and "Drive %r already exists"%(self.drive_key, ) or "Drive %r not found"%(self.drive_key, ))
		# try:
		# 	self.drive.exists()
		# except (DriveNotFoundError, CloudDrive.ConnectionError) as e:
		# 	raise DriveNotFoundError("Drive %r not found"%(self.drive_key, ))

def create_drive(Session):
	Session.test_if_drive_exists(True)
	set_index(Session, {})

GLOBAL_INDEX_LOCK = threading.Lock()

FILE_UPLOAD_PROCESS_LOCK = threading.Lock()
def process_file_upload(uploadfilename, fpath, done, args):
	FILE_UPLOAD_PROCESS_LOCK.acquire()
	print("[SENDING FILE] "+uploadfilename)
	response = user.send(988130151495774208, files=[{
		"filename": uploadfilename,
		"handle": open(fpath, "rb")
	}])
	threading.Thread(target=lambda: not time.sleep(1) and FILE_UPLOAD_PROCESS_LOCK.release()).start()
	try:
		data = response.json()
	except:
		if "stressing the resources" in response.content.decode():
			data = {"retry_after": 5}
			print("Discord Server Overloaded :(")
	if data.get("retry_after"):
		time.sleep(data["retry_after"] * 1.5)
		return process_file_upload(uploadfilename, fpath, done, args)
	if not data.get("attachments"):
		print(data)
	print("Upload Complete: "+uploadfilename)
	done(data["attachments"][0]["url"], *args)
def upload_file(uploadfilename, fpath, done=lambda:None, args=()):
	threading.Thread(target=process_file_upload, args=(uploadfilename, fpath, done, args)).start()

class PathNotFoundError(Exception): pass
class FileSystemKeyError(Exception): pass
class ChecksumMismatch(Exception): pass

START_PADDING, END_PADDING = b"\xdd\xb3\xa9c\xbc\x02,\r\xc5!\x14Y\xaa-`f", b"\x8a\x14\x03`t\xf6\xb7\xb4\xa6\n\xe6\xcb\x02\xe3r$"
def get_index_metadata(Session):
	if not Session.valid: return {}
	try:
		raw = Session.drive.read()
	except Exception as e:
		print(e)
		return {}
	if len(raw.splitlines()) == 1:
		raw = b"METADATA: {}\n" + raw
	raw = raw.splitlines()[0]
	return json.loads(raw.decode().removeprefix("METADATA: ").strip())
def get_index(Session):
	if not Session.valid: return {}
	raw = Session.drive.read()
	if len(raw.splitlines()) == 1:
		raw = b"METADATA: {}\n" + raw
	raw = raw.splitlines()[1]

	f = Fernet(Session.fernet_key)
	try:
		decrypted = f.decrypt(raw)
	except FernetInvalidToken:
		raise FileSystemKeyError
	data = json.loads(decrypted.removeprefix(START_PADDING).removesuffix(END_PADDING).decode())
	return data
def set_index(Session, data):
	if not Session.valid: return
	encrypted = Fernet(Session.fernet_key).encrypt(START_PADDING + json.dumps(data).encode() + END_PADDING)

	metadata = get_index_metadata(Session)
	metadata["location"] = Session.export_drive_key()

	encrypted = b"METADATA: " + json.dumps(metadata).encode() + b"\n" + encrypted
	Session.drive.write(encrypted)

def getPathSegments(path):
	return [seg for seg in path.split("/") if seg]

def get_index_dict(index, path):
	if type(path) == str:
		path = getPathSegments(path)
	dir = index
	build = ""
	for segment in path:
		dir = dir.get(segment)
		if dir is None:
			raise PathNotFoundError("Path not found: %s/[%s ?]"%(build, segment))
		build += "/"+segment
	return dir

def pathsplit(segments):
	if type(segments) == str:
		segments = getPathSegments(segments)
	if len(segments) == 0: return "", ""
	return len(segments) == 1 and "/" or segments[:-1], segments[-1]


def normalizePath(path):
	path = path.replace("\\", "/").replace("./", "").replace("filesystem/", "", 1)
	return path

def remove(Session, path):
	path = normalizePath(path)
	parentDirectory, file = pathsplit(path)
	index = get_index(Session)
	parentDirectoryIndex = get_index_dict(index, parentDirectory)
	if parentDirectoryIndex.get(file) is None: return print("ERR_F1: %s, %s"%(parentDirectoryIndex, file))

	originalData = parentDirectoryIndex[file]
	del parentDirectoryIndex[file]
	set_index(Session, index)
	return originalData

def isfile(Session, path):
	path = normalizePath(path)
	try:
		data = get_index_dict(get_index(Session), path)
	except PathNotFoundError:
		return False
	return data.get("size") is not None

def get_size(Session, path):
	path = normalizePath(path)
	if isfile(Session, path):
		data = get_index_dict(get_index(Session), path)
		return data.get("size") or 0
	else:
		total_size = 0
		for f in listdir(Session, path):
			total_size += get_size(Session, os.path.join(path, f))
		return total_size
	
def isdir(Session, path):
	path = normalizePath(path)
	try:
		data = get_index_dict(get_index(Session), path)
	except PathNotFoundError:
		return False
	return data.get("size") is None

def exists(Session, path):
	path = normalizePath(path)
	try:
		data = get_index_dict(get_index(Session), path)
	except PathNotFoundError:
		return False
	return True
def listdir(Session, path):
	path = normalizePath(path)
	dir = get_index_dict(get_index(Session), path)

	return list(dir.keys())

def write(Session, path, data, last_modified=None):
	global cursor

	if last_modified is None:
		last_modified = time.time()
	upload_time = time.time()
	path = normalizePath(path)
	index = get_index(Session)
	parent, file = pathsplit(path)

	locks = []
	downloadUrls_Index = {}
	cindex = 0

	SPLIT_CHUNK_SIZE = int(round(CHUNK_SIZE*0.95))

	chunks = [data[i:i + SPLIT_CHUNK_SIZE] for i in range(0, len(data), SPLIT_CHUNK_SIZE)]
	file_size = len(data)
	del data
	temp_filename = os.path.join(os.path.join(workingcwd, "temp"), uuid.uuid4().hex)

	for data in chunks:
		temp_section_filename = temp_filename+"_section_%d"%cindex
		key = Fernet.generate_key()
		fernet = Fernet(key)

		before = len(data)

		cursor = 0
		fileintegrityhash = ""
		
		with open(temp_section_filename, 'wb') as fo:
			def read(block):
				global cursor
				chunk = data[cursor:cursor+block]
				cursor += block
				if len(chunk) == 0:
					return
				enc = fernet.encrypt(chunk)
				
				return struct.pack('<I', len(enc))+enc
			zipper = GzipCompressReadStream(read)
			checksum_store = b""
			while True:
				chunkdata = zipper.read(1 << 16)
				final = len(chunkdata) == 0

				if len(checksum_store) == (1 << 19) or final:
					fileintegrityhash += hashlib.md5(checksum_store).hexdigest()
					checksum_store = b""
				if final:
					break
				fo.write(chunkdata)
				checksum_store += chunkdata
		after = os.path.getsize(temp_section_filename)
		print("COMPRESS + ENCRYPTION: %d BYTES > %d BYTES (%s%%) | checksum %r"%(before, after, before == 0 and 100.0 or (after/before*100), fileintegrityhash))

		lock = threading.Lock()
		lock.acquire()
		locks.append(lock)
		def done(url, key, cindex, lock, temp_section_filename):
			downloadUrls_Index[cindex] = ["v2", url, key.decode(), fileintegrityhash]
			os.remove(temp_section_filename)
			lock.release()


		upload_file("data%d"%cindex, temp_section_filename, done=done, args=(key, cindex, lock, temp_section_filename))

		cindex += 1

	for lock in locks:
		if lock.locked():
			lock.acquire()
			lock.release()

	downloadUrls = [None for i in range(len(downloadUrls_Index.keys()))]
	for index, value in downloadUrls_Index.items():
		downloadUrls[index] = value

	GLOBAL_INDEX_LOCK.acquire()
	index = get_index(Session)
	dir = get_index_dict(index, parent)

	dir[file] = {
		"size": file_size,
		"download_urls": downloadUrls,
		"upload_time":upload_time,
		"last_modified":last_modified,
	}

	set_index(Session, index)
	GLOBAL_INDEX_LOCK.release()

def write_directory(Session, path, folder):
	threads = []

	for f in listdir(Session, path):
		fpath = path + "/" +f
		if isdir(Session, fpath):
			newDirectory = os.path.join(folder, f)
			os.mkdir(newDirectory)
			threads += write_directory(Session, fpath, newDirectory)
		else:
			fhandle = open(os.path.join(folder, f), "wb")
			thread = threading.Thread(target=download, args=(Session, fpath, fhandle))
			thread.start()
			threads.append(thread)
	
	return threads

async def create_folder_archive(Session, handle, path, Progress=None):
	path = normalizePath(path)
	segments = getPathSegments(path)

	TEMP_FOLDER = os.path.join(os.path.join(workingcwd, "temp"), len(segments) == 0 and "root" or segments[-1])
	if os.path.isdir(TEMP_FOLDER):
		shutil.rmtree(TEMP_FOLDER)
	os.mkdir(TEMP_FOLDER)
	
	write_directory_threads = write_directory(Session, path, TEMP_FOLDER)
	Progress.listen(lambda p: print("Zip File Collection Progress: %s%%"%round(p*100, 1)))
	Progress.set_max(len(write_directory_threads))
	for thread in write_directory_threads: thread.join(); Progress.progress()
	print("All Required Files Downloaded. Zipping...")

	filesmap = []
	def mapDirectory(folder):
		for f in os.listdir(folder):
			vpath = folder + "/" +f
			if os.path.isdir(vpath):
				mapDirectory(vpath)
			else:
				filesmap.append({
					"file": vpath,
				})
	mapDirectory(TEMP_FOLDER)

	aiozip = AioZipStream(filesmap, chunksize=1 << 16)
	async for chunk in aiozip.stream():
		handle.write(chunk)
	shutil.rmtree(TEMP_FOLDER)

def rename(Session, frompath, topath):
	frompath, topath = normalizePath(frompath), normalizePath(topath)

	data = remove(Session, frompath)

	GLOBAL_INDEX_LOCK.acquire()
	index = get_index(Session)
	toparentDirectory, tofile = pathsplit(topath)
	toparentDirectoryIndex = get_index_dict(index, toparentDirectory)
	toparentDirectoryIndex[tofile] = data

	set_index(Session, index)
	GLOBAL_INDEX_LOCK.release()

def mkdir(Session, path):
	path = normalizePath(path)
	if exists(Session, path):
		raise FileExistsError("Path %r already exists!"%path)
	segments = getPathSegments(path)
	
	parentDirectory, newDirectoryName = pathsplit(segments)

	GLOBAL_INDEX_LOCK.acquire()

	index = get_index(Session)
	parentDirIndex = get_index_dict(index, parentDirectory)
	parentDirIndex[newDirectoryName] = {}

	set_index(Session, index)
	GLOBAL_INDEX_LOCK.release()

def streamUrlDownload(address, handle):
	addressversion, url, key, fileintegrityhash = None, None, None, None
	if len(address) == 2:
		(url, key) = address
	else:
		(addressversion, url, key, fileintegrityhash) = address
	temp_section_filename_encrypted = os.path.join("temp", uuid.uuid4().hex)
	print("[STREAM FILE] %s WITH KEY %s > %s"%(url, key, temp_section_filename_encrypted))
	with open(temp_section_filename_encrypted, "wb") as temp_section_handle:
		with requests.get(url, stream=True) as r:
			for chunk in r.iter_content(chunk_size=1 << 16):
				temp_section_handle.write(chunk)

	print("[STREAM FILE] DECOMPRESSING + DECRYPTING")
	fernet = Fernet(key)
	with open(temp_section_filename_encrypted, 'rb') as fileobj:
		if fileintegrityhash:
			index = 0
			while True:
				data = fileobj.read(1 << 19)
				if len(data) == 0:
					break
				chunk_checksum = hashlib.md5(data).hexdigest()
				chunk_checksum_integrity = fileintegrityhash[index * 32:(index+1) * 32]
				if chunk_checksum != chunk_checksum_integrity:
					raise ChecksumMismatch("Checksum mismatch: (chunk_checksum=%r, integrity=%r) @ byte %d"%(chunk_checksum, chunk_checksum_integrity, fileobj.tell()))
				index += 1

			fileobj.seek(0)

		gzipstream = gzip.GzipFile(None, mode='rb', fileobj=fileobj)
		while True:
			size_data = gzipstream.read(4)
			if not size_data:
				break
			chunk = gzipstream.read(struct.unpack('<I', size_data)[0])
			dec = fernet.decrypt(chunk)
			handle.write(dec)
	os.remove(temp_section_filename_encrypted)
	print("[STREAM FILE] COMPLETE")

def download(Session, path, writehandle, Progress=None):
	global nextWriteIndex
	if type(writehandle) == io.TextIOWrapper:
		assert writehandle.mode == "wb", "File handle must be in mode \"wb\""

	path = normalizePath(path)
	data = get_index_dict(get_index(Session), path)

	if Progress: Progress.listen(lambda p: print("Combine Files process: %s%%"%round(p*100, 1)))
	nextWriteIndex = 0
	def fetchContent(index, address, writehandle):
		global nextWriteIndex
		while nextWriteIndex != index:
			time.sleep(0.01)
		streamUrlDownload(address, writehandle)
		if Progress: Progress.progress()
		nextWriteIndex += 1

	if data.get("download_urls"):
		threads = []
		for index, address in enumerate(data["download_urls"]):
			thread = threading.Thread(target=fetchContent, args=(index, address, writehandle))
			thread.start()
			threads.append(thread)
		if Progress: Progress.set_max(index+1)
		for thread in threads: thread.join()
		print("combine %d files: complete"%(index+1))

def upload_directory(Session, folder, path, doasync=False):
	if not isdir(Session, path):
		mkdir(Session, path)
	
	threads = []

	for f in os.listdir(folder):
		fpath = os.path.join(folder, f)
		if os.path.isdir(fpath):
			newDirectory = path + "/" + f
			if not isdir(Session, path):
				mkdir(Session, newDirectory)
			threads += upload_directory(Session, fpath, newDirectory, doasync=True)
		else:
			thread = threading.Thread(target=write, args=(Session, path + "/" + f, open(fpath, "rb").read(), os.path.getmtime(fpath)))
			thread.start()
			threads.append(thread)
	if not doasync:
		Progress = Progression()
		Progress.listen(lambda p: print("Upload Progress: %s%%"%round(p*100, 1)))
		Progress.set_max(len(threads))
		for thread in threads: thread.join(); Progress.progress()
	return threads
