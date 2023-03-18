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
os.environ["USERPROFILE"] = os.environ.get("USERPROFILE") or os.environ["HOME"]
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
import subprocess
import hashlib
from aes import AESCipher
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
		return callback
	def unlisten(self, callback):
		return self.listeners.remove(callback)
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
class RDADrive():
	class ConnectionError(Exception): pass
	def __init__(self, info):
		self.RDAConnectionInfo = info
		self.RDAConnectionId = f"rda:{info['remote-ip']} ({info['entry-name']})"
	def get_connection_namehash_cipher(self):
		namehash = hashlib.sha256(self.RDAConnectionInfo["entry-name"].encode()).hexdigest()
		return namehash, AESCipher(namehash + self.RDAConnectionInfo["remote-passphrase"])
	def prepare_payload(self, payload):
		namehash, cipher = self.get_connection_namehash_cipher()
		return json.dumps({
			"name": namehash,
			"payload": cipher.encrypt(json.dumps(payload)).decode(),
		})
	def get_wifi_name(self):
		if sys.platform == "darwin":
			process = subprocess.Popen(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport','-I'], stdout=subprocess.PIPE)
			out, err = process.communicate()
			process.wait()
			for line in out.decode().split("\n"):
				if line.strip().startswith("SSID:"):
					return line.strip().removeprefix("SSID:").strip()
		return ""

	def on_restricted_wifi(self):
		n = self.get_wifi_name()
		for term in ["Staff", "Student", "School"]:
			if term.lower() in n.lower():
				return True
		return False
	def pre_request(self):
		print("[RDADrive] Establishing connection...")
		if self.on_restricted_wifi():
			try:
				response = requests.get(f"http://{self.RDAConnectionInfo['remote-ip']}/api/ping")
			except Exception:
				raise self.ConnectionError
			data = response.content.decode()

			# fortiguard bypass
			if response.status_code == 403 and "fortinet.net" in data:
				print("[RDADrive] Detected network restriction: fortinet.net")
				temporary_unblock_uri = data.split('onclick="document.location.href=\'', 1)[1].split("\'")[0]
				try:
					response = requests.get(temporary_unblock_uri, verify=False, allow_redirects=False)
				except Exception:
					raise self.ConnectionError
				if response.status_code == 302:
					redirect = response.headers.get("Location")
					if redirect:
						if redirect.startswith("https://"):
							redirect = "http://"+redirect.removeprefix("https://")
						try:
							response = requests.get(redirect, allow_redirects=False)
						except Exception:
							raise self.ConnectionError
						if "Authentication was successful" in response.content.decode():
							print("[RDADrive] Unblocked network restriction")
							return True

	def get(self):
		if type(_GlobalCloudDriveCache.get(self.RDAConnectionId)) == dict:
			if time.time() < _GlobalCloudDriveCache[self.RDAConnectionId]["expires"]:
				return _GlobalCloudDriveCache[self.RDAConnectionId]["data"]
			del _GlobalCloudDriveCache[self.RDAConnectionId]
		elif type(_GlobalCloudDriveCache.get(self.RDAConnectionId)) == threading.Lock:
			lock = _GlobalCloudDriveCache[self.RDAConnectionId]
			lock.acquire()
			lock.release()
			return _GlobalCloudDriveCache[self.RDAConnectionId]

		lock = threading.Lock()
		lock.acquire()
		_GlobalCloudDriveCache[self.RDAConnectionId] = lock
		self.pre_request()
		try:
			response = requests.get(f"{self.RDAConnectionInfo.get('protocol') or 'http'}://{self.RDAConnectionInfo['remote-ip']}/api/remote-drive-access", data=self.prepare_payload({"passphrase": self.RDAConnectionInfo["remote-passphrase"]}))
		except Exception:
			traceback.print_exc()
			raise self.ConnectionError
		if response.status_code == 404:
			raise DriveNotFoundError
		lock.release()
		namehash, cipher = self.get_connection_namehash_cipher()
		data = cipher.decrypt(response.content).encode()
		_GlobalCloudDriveCache[self.RDAConnectionId] = {
			"expires": time.time() + CLOUD_DRIVE_CACHE_EXPIRE,
			"data": data,
		}
		return data
	def exists(self):
		self.pre_request()
		try:
			response = requests.get(f"{self.RDAConnectionInfo.get('protocol') or 'http'}://{self.RDAConnectionInfo['remote-ip']}/api/remote-drive-access", data=self.prepare_payload({"passphrase": self.RDAConnectionInfo["remote-passphrase"]}), timeout=6)
		except:
			traceback.print_exc()
			return False
		if response.status_code == 404:
			return False
		return True
	def write(self, data):
		_GlobalCloudDriveCache[self.RDAConnectionId] = {
			"expires": time.time() + CLOUD_DRIVE_CACHE_EXPIRE,
			"data": data,
		}
		def update():
			self.pre_request()
			try:
				response = requests.put(f"{self.RDAConnectionInfo.get('protocol') or 'http'}://{self.RDAConnectionInfo['remote-ip']}/api/remote-drive-access", data=self.prepare_payload({"data": data.decode()}))
			except Exception as e:
				traceback.print_exc()
				raise self.ConnectionError
			if response.status_code == 404:
				raise DriveNotFoundError
		threading.Thread(target=update).start()
	def read(self):
		return self.get()
	def export_drive_key(self):
		return self.RDAConnectionId

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

_RamDiskSlots = {}
class RamDisk():
	def __init__(self, slot):
		self.slot = slot.removeprefix("ramdisk:").strip()
	def exists(self):
		return self.slot in _RamDiskSlots
	def read(self):
		return _RamDiskSlots[self.slot]
	def write(self, data):
		_RamDiskSlots[self.slot] = data
	def export_drive_key(self):
		return f"ramdisk:{self.slot}"

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
		if type(self.drive_key) == dict and all(map(self.drive_key.get, ["entry-name", "remote-ip", "remote-passphrase"])):
			# RDA Drive
			self.drive = RDADrive(self.drive_key)
		elif self.drive_key.startswith("cloud:"):
			# cloud drive
			self.drive = CloudDrive(self.drive_key)
		elif self.drive_key.startswith("ramdisk:"):
			self.drive = RamDisk(self.drive_key)
		else:
			self.drive = LocalDrive(self.drive_key.replace(os.environ["USERPROFILE"], r"%user%"))
		self.export_drive_key = self.drive.export_drive_key
		self.write_export_drive_key = hasattr(self.drive, "write_export_drive_key") and self.drive.write_export_drive_key or self.export_drive_key
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
def process_file_upload(uploadfilename, fhandle, done, args, progressCallback=None):

	m_pkg = user.send_op_prep(988130151495774208, files=[{
		"filename": uploadfilename,
		"handle": fhandle
	}], progressCallback=progressCallback)

	FILE_UPLOAD_PROCESS_LOCK.acquire()
	print("[SENDING FILE] "+uploadfilename)
	response = user.send(m_pkg)
	threading.Thread(target=lambda: not time.sleep(1) and FILE_UPLOAD_PROCESS_LOCK.release()).start()
	try:
		data = response.json()
	except:
		if "stressing the resources" in response.content.decode():
			data = {"retry_after": 5}
			print("Discord Server Overloaded :(")
	if data.get("retry_after"):
		print("Got 'Retry-After'")
		time.sleep(data["retry_after"] * 1.5)
		if hasattr(fhandle, "seek"): fhandle.seek(0)
		return process_file_upload(uploadfilename, fhandle, done, args, progressCallback=progressCallback)
	if not data.get("attachments"):
		print(data)
	print("Upload Complete: "+uploadfilename)
	done(data["attachments"][0]["url"], *args)
def upload_file(uploadfilename, fhandle, done=lambda:None, args=(), progressCallback=None):
	t = threading.Thread(target=process_file_upload, args=(uploadfilename, fhandle, done, args), kwargs={"progressCallback":progressCallback})
	t.start()
	return t

class PathNotFoundError(Exception): pass
class FileSystemKeyError(Exception): pass

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
	metadata["location"] = Session.write_export_drive_key()

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
		if not segment in dir: raise PathNotFoundError("Path not found: %s/[%s ?]"%(build, segment))
		dir = dir.get(segment) or {}
			
		build += "/"+segment
	return dir

def pathsplit(segments):
	if type(segments) == str:
		segments = getPathSegments(segments)
	if len(segments) == 0: return "", ""
	return len(segments) == 1 and "/" or segments[:-1], segments[-1]


def normalizePath(path):
	path = path.replace("\\", "/")
	if path.startswith("./"):
		path = path.removeprefix("./")
	if path.startswith("filesystem/"):
		path = path.removeprefix("filesystem/")
	segs = path.split("/")
	fixedsegs = []
	for index, seg in enumerate(segs):
		append = seg
		if seg == ".":
			append = None
		elif seg == "..":
			append = None
			if len(fixedsegs) >= 1:
				fixedsegs.pop(-1)
		if append:
			fixedsegs.append(append)
	return "/".join(fixedsegs)

def remove(Session, path):
	path = normalizePath(path)
	parentDirectory, file = pathsplit(path)
	index = get_index(Session)
	parentDirectoryIndex = get_index_dict(index, parentDirectory)
	if file not in parentDirectoryIndex: return print("ERR_F1: %s, %s"%(parentDirectoryIndex, file))

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
def get_last_modified(Session, path):
	path = normalizePath(path)
	if isfile(Session, path):
		data = get_index_dict(get_index(Session), path)
		return data.get("last_modified") or 0
	else:
		last_modified = 0
		for f in listdir(Session, path):
			last_modified = max(last_modified, get_last_modified(Session, os.path.join(path, f)))
		return last_modified
	
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

def write(Session, path, data, last_modified=None, Progress=None):
	if last_modified is None:
		last_modified = time.time()
	upload_time = time.time()
	path = normalizePath(path)
	index = get_index(Session)
	parent, file = pathsplit(path)

	upload_threads = []
	downloadUrls_Index = {}

	SPLIT_CHUNK_SIZE = int(round(CHUNK_SIZE*0.95))

	chunks = [data[i:i + SPLIT_CHUNK_SIZE] for i in range(0, len(data), SPLIT_CHUNK_SIZE)]
	file_size = len(data)
	del data

	current_waiting_bytes_upload = 0
	confirmed_waiting_files = 0 # the number of files that have their upload size confirmed: used to predict

	for cindex, data in enumerate(chunks):
		key = Fernet.generate_key()
		fernet = Fernet(key)

		before = len(data)

		cursor = 0
		
		fo = io.BytesIO()
		def read(block):
			nonlocal cursor
			chunk = data[cursor:cursor+block]
			cursor += block
			if len(chunk) == 0:
				return
			enc = fernet.encrypt(chunk)
			
			return struct.pack('<I', len(enc))+enc
		zipper = GzipCompressReadStream(read)
		
		while True:
			chunkdata = zipper.read(1 << 16)
			if len(chunkdata) == 0:
				break
			fo.write(chunkdata)

		after = fo.getbuffer().nbytes
		print("COMPRESS + ENCRYPTION: %d BYTES > %d BYTES (%s%%)"%(before, after, before == 0 and 100.0 or (after/before*100)))

		def done(url, key, cindex):
			downloadUrls_Index[cindex] = ["v3", {
				"address": url,
				"key": key.decode(),
			}]

			# ["v2", url, key.decode(), fileintegrityhash]
		def closure():
			last_current_file_progress = 0
			def upd_current_file_progress(command, arg):
				nonlocal last_current_file_progress, current_waiting_bytes_upload, confirmed_waiting_files
				if not Progress: return
				if command == "max":
					current_waiting_bytes_upload += arg
					confirmed_waiting_files += 1
					missing_confirm_waiting_files = (len(chunks) - confirmed_waiting_files)
					Progress.set_max(current_waiting_bytes_upload + current_waiting_bytes_upload/confirmed_waiting_files * missing_confirm_waiting_files)
				elif command == "update":
					Progress.progress(arg - last_current_file_progress)
					last_current_file_progress = arg
			upload_threads.append(
				upload_file("data%d"%cindex, fo, done=done, args=(key, cindex), progressCallback=Progress and upd_current_file_progress)
			)
		closure()
	for thread in upload_threads:
		thread.join()

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
		"last_modified":int(last_modified),
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
					"name": os.path.join(path, f),
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

def streamUrlDownload(address, handle, progress=None):
	addressversion, url, key, fileintegrityhash = None, None, None, None
	addressversion = address[0]
	if addressversion == "v2":
		(addressversion, url, key, fileintegrityhash) = address
	elif addressversion == "v3":
		(addressversion, data) = address
		url, key = data.get("address"), data.get("key")
	else:
		(url, key) = address
	
	# allocate 50% to downloading the file and 50% to decompressing + decrypting the file
	p_download = 0
	p_download_max = 0
	p_decompress_decrypt = 0
	p_decompress_decrypt_max = 0
	progress("max", 1)
	def p_send_progress():
		progress("update", 
			(p_download/p_download_max) * 0.5 + 
			(p_decompress_decrypt_max > 0 and (p_decompress_decrypt/p_decompress_decrypt_max) * 0.5 or 0)
		)

	temp_section_filename_encrypted = os.path.join("temp", uuid.uuid4().hex)
	print("[STREAM FILE] %s WITH KEY %s > %s"%(url, key, temp_section_filename_encrypted))
	with open(temp_section_filename_encrypted, "wb") as temp_section_handle:
		with requests.get(url, stream=True) as r:
			p_download_max = int(r.headers["Content-Length"])
			for chunk in r.iter_content(chunk_size=1 << 16):
				temp_section_handle.write(chunk)
				p_download += len(chunk)
				p_send_progress()

	print("[STREAM FILE] DECOMPRESSING + DECRYPTING")
	fernet = Fernet(key)
	with open(temp_section_filename_encrypted, 'rb') as fileobj:
		p_decompress_decrypt_max = os.fstat(fileobj.fileno()).st_size
		
		# hijack read to provide us with progress #hacky
		original_read = fileobj.read
		def modified_read(chunkSize):
			nonlocal p_decompress_decrypt
			p_decompress_decrypt = fileobj.tell()
			p_send_progress()
			return original_read(chunkSize)
		fileobj.read = modified_read
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
	if type(writehandle) == io.TextIOWrapper:
		assert writehandle.mode == "wb", "File handle must be in mode \"wb\""

	path = normalizePath(path)
	data = get_index_dict(get_index(Session), path)

	nextWriteIndex = 0
	def fetchContent(index, address, writehandle, upd_current_file_progress):
		nonlocal nextWriteIndex
		while nextWriteIndex != index:
			time.sleep(0.01)
		streamUrlDownload(address, writehandle, upd_current_file_progress)
		nextWriteIndex += 1

	if data.get("download_urls"):
		threads = []

		current_waiting_bytes_download, confirmed_waiting_files = 0, 0
		for index, address in enumerate(data["download_urls"]):
			def closure():
				last_current_file_progress = 0
				def upd_current_file_progress(command, arg):
					nonlocal last_current_file_progress, current_waiting_bytes_download, confirmed_waiting_files
					if not Progress: return
					if command == "max":
						current_waiting_bytes_download += arg
						confirmed_waiting_files += 1
						missing_confirm_waiting_files = (len(data["download_urls"]) - confirmed_waiting_files)
						Progress.set_max(current_waiting_bytes_download + current_waiting_bytes_download/confirmed_waiting_files * missing_confirm_waiting_files)
					elif command == "update":
						Progress.progress(arg - last_current_file_progress)
						last_current_file_progress = arg
				thread = threading.Thread(target=fetchContent, args=(index, address, writehandle, upd_current_file_progress))
				thread.start()
				threads.append(thread)
			closure()

			
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
