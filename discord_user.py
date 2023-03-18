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

import requests
import time
import json
try:
	from requests_toolbelt import (MultipartEncoder,
                               MultipartEncoderMonitor)
except ImportError:
	MultipartEncoder, MultipartEncoderMonitor = None, None

def discordhttp(method, *a, **k):
	k["headers"] = k.get("headers") or {}
	k["headers"]["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.4844.84 Safari/537.36"
	
	return method(*a, **k)

class Subscriptions():
	def __init__(self):
		self.Nitro = "Nitro"
		self.NitroClassic = "NitroClassic"
		self.NoSubscription = "None"
	
	def __call__(self, subscriptionType=None):
		subscriptionType = subscriptionType or 0
		return [self.NoSubscription, self.NitroClassic, self.Nitro][subscriptionType]

Subscriptions = Subscriptions()

class User():
	def __init__(self, token=None):
		self.token = token
	def login(self, token):
		self.token = token
	def send_op_prep(self, channelid, files, progressCallback):
		attachments = [{
						"id": fid,
						"filename": attachmentdata["filename"],
					} for fid, attachmentdata in enumerate(files)]
		data = dict({
			"payload_json": json.dumps({"content":"","nonce":None,"channel_id":channelid,"type":0,"sticker_ids":[],"attachments":attachments}),
		},**{
			"files[%d]"%fid: (attachmentdata["filename"], attachmentdata["handle"]) for fid, attachmentdata in enumerate(files)
		})
		encoder = MultipartEncoder(data)
		monitor = MultipartEncoderMonitor(encoder, lambda x: progressCallback("update", monitor.bytes_read))
		monitor.data_channelid = channelid
		progressCallback("max", encoder.len)
		return monitor
	def send(self, channelid, message="", files=[]):
		if type(channelid) == MultipartEncoderMonitor:
			# special: received package from send_op_prep()
			monitor = channelid
			return discordhttp(requests.post, f"https://discord.com/api/v9/channels/{monitor.data_channelid}/messages", headers={
				"authorization": self.token,
				"Content-Type": monitor.content_type,
			}, data=monitor)
		# files = [
		# 	{
		# 		"filename": "xxx", "handle": open("xxx", "rb")
		# 	}
		# ]
		if files:
			attachments = []
			reqfiles = {}
			for fid, attachmentdata in enumerate(files):
				attachments.append({
					"id": fid,
					"filename": attachmentdata["filename"],
				})
				reqfiles["files[%d]"%fid] = attachmentdata["handle"]
			response = discordhttp(requests.post, f"https://discord.com/api/v9/channels/{channelid}/messages", headers={
				"authorization": self.token
			}, data={
				"payload_json": json.dumps({"content":message,"nonce":None,"channel_id":channelid,"type":0,"sticker_ids":[],"attachments":attachments}),
			}, files=reqfiles)
		else:
			response = discordhttp(requests.post, f"https://discord.com/api/v9/channels/{channelid}/messages", headers={
				"authorization": self.token
			}, data={
				"content":message,
				"nonce":None,
				"tts":False,
			})
		return response
	def set_status(self, status):
		response = discordhttp(requests.patch, "https://discord.com/api/v9/users/@me/settings",headers={
			"authorization": self.token,
			"Content-Type":"application/json",
		}, data=json.dumps({
			"custom_status": {
				"text": status
		}}))
		return response
	def get_user_info(self):
		response = discordhttp(requests.get, "https://discord.com/api/v9/users/@me", headers={
			"authorization": self.token
		})
		data = response.json()
		return {
			"id": data["id"],
			"tag": data["username"]+"#"+data["discriminator"],
			"avatar_url": "https://cdn.discordapp.com/avatars/%d/%s.webp?size=80"%(data["id"], data["avatar"]),
			"email": data["email"],
		}
		print(response.content)
	def get_subscription_type(self):
		response = discordhttp(requests.get, "https://discord.com/api/v9/users/@me", headers={
			"authorization": self.token
		})
		return Subscriptions(response.json().get("premium_type"))
	def get_upload_limit(self):
		# in bytes
		# DOES NOT ACCOUNT FOR SERVER BOOST UPLOAD LIMIT INCREASE
		return {
			Subscriptions.NoSubscription: 8 * 1000 * 1000,
			Subscriptions.NitroClassic: 50 * 1000 * 1000,
			Subscriptions.Nitro: 100 * 1000 * 1000,
		}[self.get_subscription_type()]
