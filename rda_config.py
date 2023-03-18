# Allow other users of DiscordFileSystem to commit to this drive remotely (you will have to set up port forwarding)
# note: this does not mean they can access any of your drives without their passwords. it just lets them write/read to them (although they have to be encrypted, which they
# can't do without your drive password!)

# RDA: Remote Drive Access / Remote Direct Access

ALLOW = [
	# {
	# 	"entry-name": "", # unique value (has to be the same on the other end)
	# 	"passphrase": "", # hash recommended
	# 	"drive": "", # ONE drive only.
	# 	"accepting": "any", # can be a list of IP addresses
	# },
]

REMOTE = [
	# {
	# 	"entry-name": "", # unique value (has to be the same on the other end)
	# 	"remote-ip": "", # include the port, usually it's 8888!
	# 	"remote-passphrase": "",
	# 	# "protocol": "https", # optional
	# },
]