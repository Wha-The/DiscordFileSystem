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

print("Loading...")
import tornado.ioloop
import tornado.web
import tornado.websocket
import socket
import os
os.chdir(os.path.split(__file__)[0])
import json
import base64
import threading
import io
import string
import random
import time
import traceback
import uuid
import sys
import signal
import hashlib
import rsa
import mimetypes
import base64
import asyncio
from cryptography.fernet import Fernet

if not os.path.isdir("temp"):
	os.mkdir("temp")

if not os.path.isdir("confidential"):
	os.mkdir("confidential")
if not os.path.isdir("confidential/drives"):
	os.mkdir("confidential/drives")
if not os.path.isfile("confidential/ip_whitelist"):
	with open("confidential/ip_whitelist", "w") as f:
		f.write("127.0.0.1\n::1")
if os.path.isfile("confidential/cookie_secret"):
	with open("confidential/cookie_secret", "rb") as handle:
		COOKIE_SECRET = handle.read()
else:
	COOKIE_SECRET = Fernet.generate_key()
	with open("confidential/cookie_secret", "wb") as handle:
		handle.write(COOKIE_SECRET)

from aes import AESCipher
import discordfilesystem as filesystem
import rda_config as RemoteDrivesConfig

Quote = ""

def fernet_encrypt(data, key=COOKIE_SECRET):
	if type(data) == str: data = data.encode()
	return Fernet(key).encrypt(data)
def fernet_decrypt(data, key=COOKIE_SECRET):
	if not data: return
	return Fernet(key).decrypt(data)

def get_size(start_path = '.'):
	total_size = 0
	if filesystem.isfile(start_path):
		return os.path.getsize(start_path)
	for dirpath, dirnames, filenames in os.walk(start_path):
		for f in filenames:
			fp = os.path.join(dirpath, f)
			# skip if it is symbolic link
			if not os.path.islink(fp):
				total_size += os.path.getsize(fp)

	return total_size
def BackgroundProcess():
	return not sys.stdout.isatty()

class Templates_template():
	def __init__(self):
		self.BasePath = "./templates/"
	def __getattr__(self,attr):
		filename = os.path.join(self.BasePath,attr+".html")
		return filename

Templates = Templates_template()
del Templates_template

NEW_CONNECTIONS_LISTENERS = []

class BaseHandler(tornado.web.RequestHandler):
	def write_error(self, status_code, **kwargs):
		excp = kwargs['exc_info'][1]
		tb = kwargs['exc_info'][2]
		stack = traceback.extract_tb(tb)
		clean_stack = [i for i in stack if i[0][-6:] != 'gen.py' and i[0][-13:] != 'concurrent.py']
		error_msg = '{}\n{}'.format(''.join(traceback.format_list(clean_stack)), excp)
		self.set_status(status_code)
		self.write(str(excp))
	def prepare(self):
		if not self.request.uri in ["/api/remote-drive-access", "/api/ping"]:
			if self.request.remote_ip != ip and self.request.remote_ip not in open("confidential/ip_whitelist",'r').read().splitlines():
				if NEW_CONNECTIONS_LISTENERS:
					[conn.send_message(json.dumps({"connection_ip": self.request.remote_ip, "user_agent":self.request.headers.get("User-Agent") or ""})) for conn in NEW_CONNECTIONS_LISTENERS]
				self.request.connection.close()
				raise tornado.web.HTTPError(401, reason="Unauthorized IP: %r"%(self.request.remote_ip))

	def FileSystem_checkAuthenticated(self,redirect=True):
		if not self.get_database_session_from_user().valid:
			if redirect:
				self.redirect("/")
			return False
		return True
	def get_database_session_from_user(self):
		data = fernet_decrypt(self.get_secure_cookie("FileSystem_SessionInfo"))
		if not data: return filesystem.Session()
		drive, fernet_key = json.loads(data)
		return filesystem.Session(drive=drive).load_from_fernet_key(fernet_key.encode())
	def get_server_private_key_to_client(self):
		server_private_key_to_that_client = fernet_decrypt(self.get_secure_cookie("ssl_server_private_key"))
		server_private_key_to_that_client = server_private_key_to_that_client and server_private_key_to_that_client.decode()
		return server_private_key_to_that_client
	def get_shared_cipher(self):
		# encrypted_data is encrypted with an AES key
		# we can retrieve the AES key from decoding the cookie "ssl_client_aes_key"
		serverPrivateKey = self.get_server_private_key_to_client()
		if not serverPrivateKey: raise tornado.web.HTTPError(401)

		encrypted_aes_key = self.get_cookie("ssl_client_aes_key")
		try:
			decode_data = base64.b64decode(encrypted_aes_key)
		except Exception as e:
			print(e)
			raise tornado.web.HTTPError(401)
		if len(decode_data) == 127:
			hex_fixed = '00' + decode_data.hex()
			decode_data = base64.b16decode(hex_fixed.upper())

		try:
			serverPrivateKey = rsa.PrivateKey.load_pkcs1(serverPrivateKey)
		except Exception as e:
			print(e)
			raise tornado.web.HTTPError(401)
		try:
			decrypted_aes_key = rsa.decrypt(decode_data, serverPrivateKey).decode()
		except Exception as e:
			print(e)
			raise tornado.web.HTTPError(401)

		# now, return cipher with decrypted_aes_key
		try:
			cipher = AESCipher(decrypted_aes_key)
		except Exception as e:
			print(e)
			raise tornado.web.HTTPError(401)
		return cipher
	def server_decrypt(self, AES_encrypted_data):
		if not AES_encrypted_data: return
		cipher = self.get_shared_cipher()
		try:
			return cipher.decrypt(AES_encrypted_data)[:-8]
		except ValueError as err:
			if hasattr(err, "args") and len(err.args) >= 1 and err.args[0] == "Padding is incorrect.":
				raise tornado.web.HTTPError(401)
			raise
	def server_encrypt(self, data):
		cipher = self.get_shared_cipher()
		return cipher.encrypt(data + str(random.randint(1e7, 1e8)))


	
class LogoutHandler(BaseHandler):
	def get(self):
		self.clear_cookie("FileSystem_SessionInfo")
		self.redirect("/")
class ScriptsHandler(BaseHandler):
	def get(self, script=""):
		if not "." in script: script = script + ".js"
		self.set_header("Content-Type", (script.endswith(".css") and "text/css" or "application/javascript"))
		path = f"./src/{script}"
		if not ".." in path and os.path.exists(path):
			with open(path, "rb") as f:
				self.write(f.read())
			return
		self.write(f"console.error('Tried to fetch unknown script {self.request.uri}')")


# -------------- FileSystem -------------------
class FileSystemRenderHandler(BaseHandler):
	def get(self, subpath):
		if not self.FileSystem_checkAuthenticated():
			return
		self.render(Templates.filesystem_viewer, Quote=Quote)
FileSystemClients = {}
def getFileSystemHiddenFolders():
	return {[o.strip() for o in i.rsplit(":", 1)][0]:[o.strip() for o in i.rsplit(":", 1)][1] for i in open("./FileSystem_HIDDEN_FOLDERS.settings",'r').readlines() if i.strip()}

def sha256(data):
	return hashlib.sha256(data.encode()).hexdigest()

class FileSystemWebSocketHandler(tornado.websocket.WebSocketHandler, BaseHandler):

	def open(self):
		if not FileSystemClients.get(self):
			FileSystemClients[self] = {"cwd":"/"}
	def send_message(self, message):
		return self.write_message(self.server_encrypt(message))
	def on_message(self, message):
		try:
			message = json.loads(self.server_decrypt(message))
		except Exception as e:
			print("400 Bad Request: ")
			traceback.print_exc()

			self.send_message(json.dumps({"error":"400 Bad Request"}))
			return
		action = message["action"] or None
		data = message.get("data") or {}

		if action == "cd":
			currentdir = FileSystemClients[self]["cwd"]
			directory = data["dir"]
			password = data.get("password")
			directory = directory.replace("\\","/")
			if (directory !="." and not "/" in directory):
				if directory == "..":
					newdir = "/".join(currentdir.split("/")[:-1])
					newdir = newdir or "/"
				else:
					newdir = ("" if currentdir=="/" else currentdir)+"/"+directory

				if filesystem.isdir(self.get_database_session_from_user(), newdir):
					password_correct = getFileSystemHiddenFolders().get(f"{self.get_database_session_from_user().drive_key}:{newdir}")
					if password_correct and directory != "..":
						shouldsendpasswordIncorrect = False
						passwordIncorrect = password != password_correct
						if password and passwordIncorrect:
							shouldsendpasswordIncorrect = True
						
						if passwordIncorrect: return self.send_message(json.dumps({"action":action,"passwordRequired":True,"passwordIncorrect":shouldsendpasswordIncorrect,"cd":directory}))
						self.send_message(json.dumps({"action":action,"passwordRequired":False,"passwordIncorrect":shouldsendpasswordIncorrect,"cd":directory}))
					FileSystemClients[self]["cwd"] = newdir.replace("\\","/")

			self.send_message(json.dumps({"action":action,"error":False,"success":True}))
		elif action == "getCDContents":
			cwd = FileSystemClients[self]["cwd"]
			afterselect = data.get("afterselect")
			dirlisting = "./filesystem"+cwd
			
			dir_list = []
			stick_to_end = []
			for item in filesystem.listdir(self.get_database_session_from_user(), dirlisting):
				if item.startswith("."):
					stick_to_end.append(item)
				else:
					dir_list.append(item)
			dir_list.extend(stick_to_end)

			self.send_message(json.dumps({
				"action":action,
				"cwd":cwd,
				"drive":self.get_database_session_from_user().export_drive_key(),
				"files":[
					{
						"name":file,
						"isfile":filesystem.isfile(self.get_database_session_from_user(), os.path.join(dirlisting,file)),
						"protected":bool(getFileSystemHiddenFolders().get(f"{self.get_database_session_from_user().drive_key}:{cwd}"+file.replace("\\","/"))),
						"size":filesystem.get_size(self.get_database_session_from_user(), "./filesystem"+cwd+"/"+file.replace("\\","/")),
						"lastmodified": filesystem.get_last_modified(self.get_database_session_from_user(), "./filesystem"+cwd+"/"+file.replace("\\","/")),
						"metadata": filesystem.get_metadata(self.get_database_session_from_user(), "./filesystem"+cwd+"/"+file.replace("\\","/")),
						#"filesinside":(not bool(getFileSystemHiddenFolders().get(f"{self.get_database_session_from_user().drive_key}:{cwd}"+file.replace("\\","/"))) and filesystem.isdir(self.get_database_session_from_user(), os.path.join(dirlisting,file)) and filesystem.listdir(self.get_database_session_from_user(), os.path.join(dirlisting,file)) )
					}
					for file in dir_list if (data.get("showhiddenfiles") or not file.startswith("."))
					],
				"afterselect":afterselect
				}))
		elif action == "downloadFile":
			file = data["file"]
			cwd = FileSystemClients[self]["cwd"]
			abspath = os.path.join(cwd, file).replace("\\","/")

			accesskey = uuid.uuid4().hex
			progresstrackid = uuid.uuid4().hex

			GlobalProgressDict[progresstrackid] = [[], filesystem.Progression()]
			FileDownloadAccessKeys[accesskey] = [abspath, progresstrackid]
			
			def cleanup():
				time.sleep(60 * 60 * 60)
				if FileDownloadAccessKeys.get(accesskey): FileDownloadAccessKeys.pop(accesskey)
				if GlobalProgressDict.get(progresstrackid): GlobalProgressDict.pop(progresstrackid)
			threading.Thread(target=cleanup).start()
			print(f"Requested download link, access: {accesskey}, progress: {progresstrackid}")
			fname = file
			if filesystem.isdir(self.get_database_session_from_user(), abspath):
				fname += ".zip"
			self.send_message(json.dumps({"action":action, "filename": fname, "url":f"/api/download?accesskey={accesskey}", "progress":progresstrackid}))

		elif action == "delFile":
			file = data["file"]
			cwd = FileSystemClients[self]["cwd"]
			fpath = os.path.join(cwd, file)
			fpath = fpath.replace("\\","/")
			if not "/" in file:
				if filesystem.isfile(self.get_database_session_from_user(), fpath) or filesystem.isdir(self.get_database_session_from_user(), fpath):
					if filesystem.isdir(self.get_database_session_from_user(), fpath) and getFileSystemHiddenFolders().get(f"{self.get_database_session_from_user().drive_key}:{fpath}"+file): return
					if not filesystem.isdir(self.get_database_session_from_user(), "/.recycle"):
						filesystem.mkdir(self.get_database_session_from_user(), "/.recycle")
					if fpath.startswith("/.recycle"):
						filesystem.remove(self.get_database_session_from_user(), fpath)
					else:
						filesystem.rename(self.get_database_session_from_user(), fpath, "/.recycle/"+file)
					
			self.send_message(json.dumps({"action":action,"success":True}))
		elif action == "renFile":
			file = data["from"].replace("\\","/")
			file2 = data["to"].replace("\\","/")
			cwd = FileSystemClients[self]["cwd"]
			fpath = os.path.join("./filesystem"+cwd,file)
			fpath2 = os.path.join("./filesystem"+cwd,file2)
			#if not "/" in file and not "/" in file2:

			if filesystem.exists(self.get_database_session_from_user(), fpath) and not filesystem.exists(self.get_database_session_from_user(), fpath2):
				if not getFileSystemHiddenFolders().get(f"{self.get_database_session_from_user().drive_key}:{fpath}"+file):
					filesystem.rename(self.get_database_session_from_user(), fpath, fpath2)
			self.send_message(json.dumps({"action":action,"success":True}))
		elif action == "newFolder":
			cwd = FileSystemClients[self]["cwd"]
			newfolder = "Folder"
			p = os.path.join("./filesystem"+cwd,newfolder)
			if not filesystem.isdir(self.get_database_session_from_user(), p):
				filesystem.mkdir(self.get_database_session_from_user(), p)
			self.send_message(json.dumps({"action":action,"afterselect":newfolder}))

	def on_close(self):
		del FileSystemClients[self]

GlobalProgressDict = {}

class FileSystemUploadHandler(BaseHandler):
	def post(self):
		file = self.request.files["file"][0]
		try:
			data = json.loads(self.get_argument("data"))
		except:
			self.set_status(400)
			self.write("400: Bad Request")
			return
		path = data.get("path")
		if not path or ".." in path:
			return
		print("Upload Queued: "+file["filename"])
		progresstrackid = uuid.uuid4().hex
		GlobalProgressDict[progresstrackid] = [[], filesystem.Progression()]
		t = threading.Thread(target=filesystem.write, args=(self.get_database_session_from_user(), os.path.join("./filesystem"+path,file["filename"]), file["body"], int(data.get("last_modified"))), kwargs={"Progress": GlobalProgressDict[progresstrackid][1]})
		t.start()
		def thread_c():
			t.join()
			if GlobalProgressDict.get(progresstrackid):
				for client in GlobalProgressDict[progresstrackid][0]:
					io_loop.asyncio_loop.call_soon_threadsafe(lambda: client.send_message(json.dumps({"completed": True})))
				del GlobalProgressDict[progresstrackid]
		t2 = threading.Thread(target=thread_c)
		t2.start()
		self.write(json.dumps({"success":True, "progress": progresstrackid}))

class FileProgressWebSocketHandler(tornado.websocket.WebSocketHandler, BaseHandler):
	def on_open(self):
		pass # nothing to process
	def send_message(self, message):
		return self.write_message(self.server_encrypt(message))
	def on_message(self, message):
		try:
			message = json.loads(self.server_decrypt(message))
		except Exception as e:
			print("400 Bad Request: ")
			traceback.print_exc()

			self.send_message(json.dumps({"error":"400 Bad Request"}))
			return
		action = message.get("action")
		data = message.get("data") or {}
		if action == "ListenFileProgress":
			progressid = data["progressid"]
			if GlobalProgressDict.get(progressid):
				GlobalProgressDict[progressid][0].append(self)
				c = GlobalProgressDict[progressid][1].listen(lambda p: io_loop.asyncio_loop.call_soon_threadsafe(lambda: self.send_message(json.dumps({"progress": p}))))
				
				if hasattr(self, "_open_progress_listner"):
					self._open_progress_listner[0].unlisten(self._open_progress_listner[1])
					self._open_progress_listner[2].remove(self)
					del self._open_progress_listner

				self._open_progress_listner = (GlobalProgressDict[progressid][1], c, GlobalProgressDict[progressid][0])
			else:
				self.send_message(json.dumps({"progress": 1}))
				self.send_message(json.dumps({"completed": True}))
				print("tried to listen to progress that doesn't exist? pid: "+progressid)
	def on_close(self):
		if hasattr(self, "_open_progress_listner"):
			self._open_progress_listner[0].unlisten(self._open_progress_listner[1])
			self._open_progress_listner[2].remove(self)
			del self._open_progress_listner

FileDownloadAccessKeys = {}
class FileSystemDownloadHandler(BaseHandler):
	def complete_progress(self, progresstrackid):
		if GlobalProgressDict.get(progresstrackid):
			for client in GlobalProgressDict[progresstrackid][0]:
				io_loop.asyncio_loop.call_soon_threadsafe(lambda: client.send_message(json.dumps({"completed": True})))
			del GlobalProgressDict[progresstrackid]
	async def get(self):
		if not self.FileSystem_checkAuthenticated():
			return
		accesskey = self.get_argument("accesskey","")
		if not FileDownloadAccessKeys.get(accesskey):
			self.set_status(401)
			return self.write("Access Key invalid/expired")
		path = ("./filesystem"+FileDownloadAccessKeys[accesskey][0])
		file_name = os.path.split(path)[1]
		if ".." in path:
			self.write("Illegal .. in filename")
			return
		self.set_header("Cache-Control", "no-cache")
		if filesystem.isfile(self.get_database_session_from_user(), path):
			self._auto_finish = False
			_, dwFileName = filesystem.pathsplit(file_name)

			if self.get_argument("content-type", None):
				self.set_header("Content-Type", self.get_argument("content-type"))
			else:
				self.set_header('Content-Type', 'application/octet-stream')
				self.set_header('Content-Disposition', f"attachment; filename=\"{dwFileName.replace(',', '')}\"")
			#self.set_header("Content-Length", filesystem.get_size(self.get_database_session_from_user(), path))
			def thread_c():
				filesystem.download(self.get_database_session_from_user(), path, self, Progress=GlobalProgressDict[FileDownloadAccessKeys[accesskey][1]][1])
				self.complete_progress(FileDownloadAccessKeys[accesskey][1])
				io_loop.asyncio_loop.call_soon_threadsafe(self.finish)
			threading.Thread(target=thread_c).start()
			return

		if self.get_argument("password", None) != getFileSystemHiddenFolders().get(f"{self.get_database_session_from_user().drive_key}:"+file_name):
			self.set_header('Content-Type', 'text/html')
			self.write("Incorrect Password.")
			self.finish()
			return
		self._auto_finish = False
		self.set_header('Content-Type', 'application/octet-stream')
		firstname = os.path.split(file_name)[-1].replace(",", "")
		self.set_header('Content-Disposition', 'attachment; filename=' + (firstname+".zip"))
		async def thread_c():
			await filesystem.create_folder_archive(self.get_database_session_from_user(), self, path, Progress=GlobalProgressDict[FileDownloadAccessKeys[accesskey][1]][1])
			self.complete_progress(FileDownloadAccessKeys[accesskey][1])
			io_loop.asyncio_loop.call_soon_threadsafe(self.finish)
		threading.Thread(target=asyncio.run, args=(thread_c(),)).start()

class FileSystemLoginHandler(BaseHandler):
	def get(self):
		if self.FileSystem_checkAuthenticated(redirect=False): return self.redirect("/filesystem/")
		self.render(Templates.filesystem_login, Quote=Quote, connectingFromLocalMachine=self.request.remote_ip in ["::1", "127.0.0.1"])
	def post(self):
		drive = self.server_decrypt(self.get_argument("drive",""))
		password = self.server_decrypt(self.get_argument("password",""))
		if drive.startswith("rda:"):
			xdrive = drive
			drive = None
			for remote in RemoteDrivesConfig.REMOTE:
				x_compare = f"rda:{remote['remote-ip']} ({remote['entry-name']})"
				if xdrive == x_compare:
					drive = remote
			if not drive:
				return self.write(self.server_encrypt(json.dumps({"error":"Unknown RDA entry. "})))
		try:
			session = filesystem.Session(drive=drive, key=password)
			session.test_if_drive_exists()
		except filesystem.DriveNotFoundError as drivenotfounderror:
			return self.write(self.server_encrypt(json.dumps({"error": tornado.escape.xhtml_escape(str(drivenotfounderror))})))
		
		if not session.test_fernet_key():
			self.write(self.server_encrypt(json.dumps({"error":"Incorrect password, unable to decrypt drive."})))
			return
		self.set_secure_cookie("FileSystem_SessionInfo", fernet_encrypt(json.dumps([session.drive_key, session.fernet_key.decode()])), expires_days=None)
		self.write(self.server_encrypt(json.dumps({"content":"/filesystem"})))
class CreateDriveHandler(BaseHandler):
	def get(self):
		self.render(Templates.filesystem_create_drive, Quote=Quote)
	def post(self):
		drive = self.server_decrypt(self.get_argument("drive",""))
		password = self.server_decrypt(self.get_argument("password",""))
		if not drive or not password: raise tornado.web.HTTPError(400)
		try:
			filesystem.create_drive(filesystem.Session(drive=drive, key=password))
		except Exception as e:
			traceback.print_exc()
			return self.write({"error":str(e)})
		self.write({"content":"/", "message":"Success! Please login to your drive."})

class RemoteDriveAccess(BaseHandler):
	def parse_data(self):
		# x- prefixed variables = server variables; f-prefixed variables = input variables;
		try:
			data = json.loads(self.request.body)
			f_entry_name_hashed, f_payload_encrypted = data["name"], data["payload"]
		except Exception:
			raise tornado.web.HTTPError(400, reason="Invalid Payload")

		# fetch passphrase for entry_name and attempt to decrypt
		for x_entry in RemoteDrivesConfig.ALLOW:
			x_entry_name_hashed = hashlib.sha256(x_entry["entry-name"].encode()).hexdigest()
			if x_entry_name_hashed == f_entry_name_hashed:
				# found our entry!
				x_entry_passphrase = x_entry["passphrase"]
				# attempt to decrypt payload with passphrase
				try:
					cipher = AESCipher(x_entry_name_hashed + x_entry_passphrase)
					f_payload = json.loads(cipher.decrypt(f_payload_encrypted))
				except Exception:
					traceback.print_exc()
					raise tornado.web.HTTPError(400, reason="Invalid Passphrase")

				return x_entry, f_payload, cipher
		raise tornado.web.HTTPError(404, reason="Invalid entry-name")

	def get(self):
		# get = read
		entry, data, cipher = self.parse_data()
		if entry.get("accepting") and entry["accepting"] != "any":
			if self.request.remote_ip not in entry["accepting"]:
				raise tornado.web.HTTPError(401, reason="Unauthorized IP")
		drive = entry.get("drive")
		if data.get("passphrase") != entry["passphrase"]: raise tornado.web.HTTPError(401, "Unauthorized") # prevent brute force attacks. as you can see we require no data, and this is scary since the only way we are able to
		# verify the password is with the data
		with open(os.path.join(filesystem.workingcwd, "confidential/drives/%s.sfsdrive"%(drive,)), "rb") as f:
			self.write(cipher.encrypt(f.read().decode()))

	def put(self):
		# put = write
		entry, data, cipher = self.parse_data()
		if entry.get("accepting") and entry["accepting"] != "any":
			if self.request.remote_ip not in entry["accepting"]:
				raise tornado.web.HTTPError(401, reason="Unauthorized IP")
		drive = entry.get("drive")
		with open(os.path.join(filesystem.workingcwd, "confidential/drives/%s.sfsdrive"%(drive,)), "w") as f:
			f.write(data["data"])

class ResourcesHandler(BaseHandler):
	def get(self):
		file_name = self.get_argument("filename","")
		path = ("./resources/"+file_name)
		if not path:
			self.write("Please provide a filename")
			return
		if ".." in path:
			self.write("Illegal .. in filename")
			return
		if not os.path.isfile(path):
			self.write("Unknown file "+file_name)
			return
		buf_size = 4096
		self.set_header('Content-Type', 'application/octet-stream')
		self.set_header('Content-Disposition', 'attachment; filename=' + os.path.split(file_name)[-1])
		with open(path, 'rb') as f:
			while True:
				data = f.read(buf_size)
				if not data:
					break
				self.write(data)
		self.finish()
class FaviconHandler(BaseHandler):
	def get(self):
		return self.redirect("/resource?filename=favicon.ico")
class FileSystemRedirector(BaseHandler):
	def get(self):
		return self.redirect("/filesystem/")
class GetDrivesHandler(BaseHandler):
	def get(self):
		drives = []
		for drive in os.listdir("confidential/drives/"):
			if drive.startswith("."): continue
			driveName = os.path.splitext(drive)[0]
			if driveName == "main":
				drives.insert(0, driveName)
			else:
				drives.append(driveName)

		for remote in RemoteDrivesConfig.REMOTE:
			drives.append(f"rda:{remote['remote-ip']} ({remote['entry-name']})")
				
		self.write(self.server_encrypt(json.dumps(drives)))

ConnectedClients = set()
class InfoWebSocketHandler(tornado.websocket.WebSocketHandler):
	def open(self):
		ConnectedClients.add(self)
	def on_message(self):
		self.write_message(json.dumps({"action":"unknown"}))
	def on_close(self):
		ConnectedClients.remove(self)
class GenerateRSAKey(BaseHandler):
	def post(self):
		publicKey, privateKey = rsa.newkeys(512)
		# send back the public key
		# save the private key as an encrypted cookie for later use
		self.set_secure_cookie("ssl_server_private_key", fernet_encrypt(privateKey.save_pkcs1()), expires_days=None)
		self.write({"key": publicKey.save_pkcs1().decode()})

class GetCloudFileDriveProtocolHelp(BaseHandler):
	def get(self):
		self.write(self.server_encrypt("""\
If you have a .sfs file, you can load that drive file by simply typing in "file:PATH_TO_DRIVE" or (preferred) drag that file over the login screen (does not work if it is downloaded from someone else's computer).
Example: file:C:\\Users\\root\\Documents\\drive.sfs
========================
If you and your friend want to share a drive, you may find a cloud host who can host your drive for the both of you (The cloud host cannot see your files without knowing your drive password).
Example: cloud:https://www.yourcloudhost.com/drives/youandyourfriend.sfsdrive\
"""))

class AllowNewIPAddress(BaseHandler):
	def get(self):
		if self.request.remote_ip not in ["::1", "127.0.0.1"]: 
			raise tornado.web.HTTPError(401, reason="Please connect from your local machine (connecting from %r)"%self.request.remote_ip)
		self.render(Templates.filesystem_allow_new_ip, Quote=Quote, href="http://%s:%d/"%(ip,PORT))

class ListenForNewDevicesWebSocketHandler(tornado.websocket.WebSocketHandler, BaseHandler):
	def open(self):
		if self.request.remote_ip not in ["::1", "127.0.0.1"]:
			self.close() 
			raise tornado.web.HTTPError(401, reason="Please connect from your local machine (connecting from %r)"%self.request.remote_ip)
		NEW_CONNECTIONS_LISTENERS.append(self)
	def send_message(self, message):
		return self.write_message(self.server_encrypt(message))
	def on_close(self):
		NEW_CONNECTIONS_LISTENERS.remove(self)
class AcceptIPAddressHandler(BaseHandler):
	def post(self):
		if self.request.remote_ip not in ["::1", "127.0.0.1"]: 
			raise tornado.web.HTTPError(401, reason="Please connect from your local machine (connecting from %r)"%self.request.remote_ip)
		ip = self.server_decrypt(self.get_argument("ip", None))
		if ip and ip not in open("confidential/ip_whitelist",'r').read().splitlines():
			with open("confidential/ip_whitelist",'a') as f:
				f.write("\n"+ip)
			return self.write(self.server_encrypt(json.dumps({"success": True, "message": "Success! Please reload the page on your device!"})))
		self.write(self.server_encrypt(json.dumps({"success": False, "message": "Something went wrong, please try again!"})))

class PingHandler(BaseHandler):
	def get(self):
		self.write("pong")

class ErrorHandler(BaseHandler):
	def prepare(self):
		super().prepare()
		raise tornado.web.HTTPError(404, reason="not found")

class App(tornado.web.Application):
	is_closing = False
	def signal_handler(self, signum, frame):
		print("Wait...")
		self.is_closing = True

	def try_exit(self):
		if self.is_closing:
			print("Preparing to exit...")
			print("Disconnecting all clients...")
			[[client.write_message(json.dumps({"action":"servershutdown"})),client.close()] for client in ConnectedClients]
			print("Shutting down webserver...")
			tornado.ioloop.IOLoop.instance().stop()
			print("Finishing up...")
			quit()
def make_app():
	settings = {
		'debug':True,
		"cookie_secret":COOKIE_SECRET,
	}
	return App([
		(r"/", FileSystemLoginHandler),
		(r"/filesystem/(.*)",FileSystemRenderHandler),
		(r"/filesystem", FileSystemRedirector),
		(r"/create_drive", CreateDriveHandler),
		(r"/allow-new-device", AllowNewIPAddress),
		(r"/logout",LogoutHandler),

		(r"/src/(?P<script>[\w\.-]+)",ScriptsHandler),
		(r"/resource",ResourcesHandler),
		(r"/favicon.ico", FaviconHandler),
		(r"/api/download",FileSystemDownloadHandler),
		(r"/api/fetch_local_drives", GetDrivesHandler),
		(r"/api/upload", FileSystemUploadHandler),
		(r"/api/remote-drive-access", RemoteDriveAccess),
		(r"/api/get_cloudfile_driveprotocol_help", GetCloudFileDriveProtocolHelp),

		(r"/api/websocket", FileSystemWebSocketHandler),
		(r"/api/file_progress_websocket", FileProgressWebSocketHandler),
		(r"/api/listen_for_new_devices_websocket", ListenForNewDevicesWebSocketHandler),
		(r"/api/accept_ip", AcceptIPAddressHandler),
		(r"/api/ping", PingHandler),
		(r"/info_websocket",InfoWebSocketHandler),

		(r"/rsa_generate", GenerateRSAKey),
	], default_handler_class=ErrorHandler, **settings),settings

if __name__ == "__main__":
	PORT = 8888

	app,settings = make_app()

	signal.signal(signal.SIGINT, app.signal_handler)

	server = tornado.httpserver.HTTPServer(app, max_buffer_size=10485760000)
	
	try:
		server.listen(PORT)
	except Exception as e:
		print("FATAL ERROR: "+str(e))
		print("Killing Process with port "+str(PORT)+"...")
		from psutil import process_iter

		for proc in process_iter():
			for conns in proc.connections(kind='inet'):
				if conns.laddr.port == PORT:
					proc.send_signal(signal.SIGTERM) # or SIGKILL
		print("Killed")
		print("Retrying port in a second...")
		time.sleep(1)
		try:
			server.listen(PORT)
		except Exception as e:
			print("error while retrying port: "+str(e))
			sys.exit(0)
		del process_iter
	ip = socket.gethostbyname(socket.gethostname())
	print("Started server")
	print("Visit http://%s:%d/"%(ip,PORT))

	tornado.ioloop.PeriodicCallback(app.try_exit, 1000).start()
	tornado.ioloop.IOLoop.configure("tornado.platform.asyncio.AsyncIOLoop")
	io_loop = tornado.ioloop.IOLoop.current()
	asyncio.set_event_loop(io_loop.asyncio_loop)
	tornado.ioloop.IOLoop.instance().start()
