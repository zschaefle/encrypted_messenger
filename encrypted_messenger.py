import socket
from threading import Thread
import random

PORT = 25000 # Random default from ports not normally used, >= 2^10

uint32_mask = (1 << 32) - 1
uint64_mask = (1 << 64) - 1
uint128_mask = (1 << 128) - 1

# generated from sage math, `p = random_prime(2^16)`; `g = primative_root(p)`
p = 47533
g = 3
P_LEN = len(str(p))
# I would've preferred to use higher primes, but they become prohibitively
# expensive when using regular python to perform exponentiation with
# `a = random.randint(0,p-1)` values as the exponent
# generating in the 2^64 range of primes would have been better, given the inputs and outputs
# of the PRG/PRF/Feistel



# # CTR mode encryption, if you wanna use that instead of CBC which is the current implementation
# def Enc(k, m):
# 	# CTR mode
# 	m = bytes(m,'utf-8')
# 	IV = random.randint(0, 2**128) # can be represented as a 16-byte object
# 	IV_out = IV.to_bytes(16, 'big')
# 	sizeoftailing = 16 - (len(m) % 16)
# 	tail = sizeoftailing.to_bytes(sizeoftailing,'big')
# 	m = m + tail
# 	c = IV_out
# 	for i in range(len(m) // 16):
# 		block = m[i*16:(i+1)*16]
# 		block_asint = int().from_bytes(block, 'big')
# 		c_i = block_asint ^ Feistel(k, IV)
# 		c_i = c_i.to_bytes(16, 'big')
# 		c = c + c_i
# 		IV += 1
# 	return c

# def Dec(k, c):
#	# CTR mode
# 	IV = int.from_bytes(c[:16], 'big')
# 	c = c[16:]
# 	m = b''
# 	for i in range(len(c) // 16):
# 		block = c[i*16:(i+1)*16]
# 		block_asint = int().from_bytes(block, 'big')
# 		m_i = block_asint ^ Feistel(k, IV)
# 		m_i = m_i.to_bytes(16, 'big')
# 		m = m + m_i
# 		IV += 1
# 	tailsize = int().from_bytes(m[-1:], 'big')
# 	m = m[:-tailsize]
# 	return m

"""
CBC mode encryption, uses the feistel cypher below for it's PRP function
"""

def Enc(k, m):
	# CBC mode
	if (type(m) == type('')):
		m = bytes(m,'utf-8')
	IV = random.randint(0, 2**128) # can be represented as a 16-byte object
	xorkey = IV
	IV_out = IV.to_bytes(16, 'big')
	sizeoftailing = 16 - (len(m) % 16)
	tail = sizeoftailing.to_bytes(sizeoftailing,'big')
	m = m + tail
	c = IV_out
	for i in range(len(m) // 16):
		block = m[i*16:(i+1)*16]
		block_asint = int().from_bytes(block, 'big')
		c_i = Feistel(k, block_asint ^ xorkey)
		xorkey = c_i
		c_i = c_i.to_bytes(16, 'big')
		c = c + c_i
	return c

def Dec(k, c):
	# CBC mode
	xorkey = int.from_bytes(c[:16], 'big')
	c = c[16:]
	m = b''
	for i in range(len(c) // 16):
		block = c[i*16:(i+1)*16]
		block_asint = int().from_bytes(block, 'big')
		m_i = FeistelInverse(k, block_asint) ^ xorkey
		xorkey = block_asint
		m_i = m_i.to_bytes(16, 'big')
		m = m + m_i
	tailsize = int().from_bytes(m[-1:], 'big')
	m = m[:-tailsize]
	return m

"""
Feistell cypher implementations
"""

def Feistel(k, inval):
	firsthalf = (inval >> 64) & uint64_mask
	secondhalf = inval & uint64_mask
	x,y = _feistel(k,firsthalf,secondhalf)
	x,y = _feistel(k,x,y)
	x,y = _feistel(k,x,y)
	return (x << 64) | y

def FeistelInverse(k, inval):
	firsthalf = (inval >> 64) & uint64_mask
	secondhalf = inval & uint64_mask
	x,y = _feistelInv(k,firsthalf,secondhalf)
	x,y = _feistelInv(k,x,y)
	x,y = _feistelInv(k,x,y)
	return (x << 64) | y

def _feistel(k, x, y):
	xorkey = PRF(k,y)
	return y, x ^ xorkey

def _feistelInv(k, x, y):
	return y ^ PRF(k,x), x


"""
A PRG constructed following an implementation of pcg-random.org,
translated from c to python, and a PRF built using it.
"""

def PRF(k, n):
	# Reconstructing a generator each time with the same k,n gives the same pseudorandom values
	generator = PRG(n,k)
	fh = generator.nextInt()
	sh = generator.nextInt()
	# output space = [0, 2 ** 32 - 1] = [0, 4294967295] from PRG.nextInt
	# so this gets a random number, then another, and "appends" them,
	# for 2 ** 64 output space.
	return (fh << 32) | sh
	

class PRG():
	"""A class representing/handling a PRG's initialization and return values."""
	def __init__(self, state, inc):
		self.state = state & uint64_mask
		self.inc = (inc|1) & uint64_mask
		while self.nextInt() == 0:
			# clean up early calls where state isn't taking up the full 'uint64', causing 0 outputs, possibly multiple times
			# If the initial state wouldn't return a zero, this is called once anyways. But since that will always happen,
			# there should be no reason to worry about 0 returns unless internal values are set externally after initialization
			continue
	
	def nextInt(self):
		# PRG defined by the following source in c, translated to python
		# https://www.pcg-random.org/download.html
		oldstate = self.state
		self.state = (oldstate * 6364136223846793005 + (self.inc)) & uint64_mask
		xorshifted = (((oldstate >> 18) ^ oldstate) >> 27) & uint32_mask
		rot = (oldstate >> 59) & uint32_mask
		return ((xorshifted >> rot) | (xorshifted << ((-rot) & 31)) & uint32_mask) & uint32_mask

class Connection():
	"""A Class handling aspects of a connection, including helper functions for sending and recieving."""
	def __init__(self, c_socket, c_addr):
		self.client = c_socket
		self.addr = c_addr
		self.secret = random.randint(0,p-1)
		self.pubkey = (g ** self.secret) % p
		self.key = None
		self.name = None

	def setKey(self, key):
		self.key = key

	def setName(self, name):
		self.name = name

	def send(self, message):
		c = Enc(self.key, message) + b'0'
		self.client.sendall(c)
		return c

	def recv(self, include_raw=False):
		c = self.client.recv(1024)
		while self.key is not None and (len(c) % 16 != 1 and c[-1] != b'0'[0]):
			# encrypted messages should be multiples of 16, given the block length used,
			# plus one b'0' byte that is added to indicate the end of a message, to help
			# notify for cases where len(m) is a multiple of 1024 exactly
			c += self.client.recv(1024)
			# However, this is also used by the 'eavesdropper' mode, so if it doesn't have
			# a key, then the assumption is that it'll just keep being looped and displayed
			# regardless of what the length is, since we can't decrypt it anyways
		if self.key is not None:
			c = c[:-1] # remove trailing b'0', indicator of end.
		if self.key:
			if include_raw:
				return Dec(self.key, c), c
			return Dec(self.key, c)
		else:
			return c

	def close(self):
		self.client.close()

class Server():
	"""
	The class representing the hub server.
	This server uses a password as vetting for what connections should be handled as users
	and which get handled as eavesdroppers.
	"""
	def __init__(self):
		# Constructs a server instance, establishing the vetting password and beginning a routine
		# that listens passively for connections and then performs the handshake routine.
		self.psw = bytes(input("What is this server's password? "), 'utf-8')
		while len(self.psw) == 0 or len(self.psw) > 1000:
			print("Please select a password between 1 and 1000 characters long")
			self.psw = bytes(input("What is this server's password? "), 'utf-8')
		self.connections = {} # {socket.socket : Connection} dictionary of "users"
		self.eavesdroppers = [] # [socket.socket] list of "eavesdroppers"
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP setup
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind(('',PORT))
		s.listen(5) # queue of 5 max unprocessed connections
		print("Local IP: ", socket.gethostbyname(socket.gethostname())) # so you don't need to look it up for local connections
		# need external things to find what the non-local IP is
		while True:
			conn, addr = s.accept()
			if self.handshake(conn, addr): # check if the connection is a user or eavesdropper
				# If user, start a reciever thread for it
				print('Connection: ', addr)
				Thread(target=self.reciever, args=(conn,)).start()
			else:
				# Otherwise, add it to the eavesdropper sending list
				self.eavesdroppers.append(conn)
				print('Connect from {} failed, added as eavesdropper'.format(addr))

	def reciever(self, client):
		# One of these should be running in a thread for each client connected.
		# Listens for messages, then passes the decoded message to be sent to all
		# other connections, and the recieved cyphertext to all eavesdropping connections
		info = self.connections[client]
		while True:
			msg, raw = info.recv(include_raw=True)
			self.alert_eavesdroppers(raw)
			print (client, msg)
			self.send(msg, client)

	def alert_eavesdroppers(self, msg):
		# Sends data to all the eavesdroppers
		# Any failure is assumed to indicate that the eavesdropper is no longer
		# listening, so it closes the connection
		if (type(msg) == type('')):
			msg = msg.encode('utf-8')
		remove_eavesdroppers = []
		for e in self.eavesdroppers:
			try:
				e.sendall(msg)
			except Exception as ex:
				print (ex, e)
				remove_eavesdroppers.append(e)
		for e in set(remove_eavesdroppers):
			try:
				e.close()
			finally:
				self.eavesdroppers.remove(e)


	def send(self, message, source):
		# Sends the message to all users, encrypting with their respective keys and
		# also sending to the encrypted texts to the eavesdroppers. If sending to users
		# fails, then it is assumed that the socket is dead, so it closes it.
		msg = message
		if type(msg) != type(b''):
			msg = bytes(msg,'utf8')
		if source is not None:
			info = self.connections[source]
			msg = info.name + b' (' + info.addr[0].encode('utf-8') + b'): '+ msg
		remove_clients = []
		for client in self.connections:
			if client == source:
				continue
			try:
				c = self.connections[client].send(msg)
				self.alert_eavesdroppers(c)
			except Exception as e:
				remove_clients.append(client)

		# clean dead connections
		for c in remove_clients:
			try:
				self.connections[c].close()
			finally:
				del self.connections[c]


	def handshake(self, conn, addr):
		# server side of the connection handshake
		# Use Diffe-Hellman exchange to establish a key
		# then test password
		# then either get a "name" to display to other users, or designate it as an eavesdropper
		info = Connection(conn, addr)
		self.connections[conn] = info
		a = info.secret
		k = info.pubkey
		m = bytes(str(k),'utf-8')
		conn.sendall(m)
		self.alert_eavesdroppers(m)
		m = conn.recv(P_LEN).decode('utf-8')
		self.alert_eavesdroppers(m)
		key = (int(m) ** a) % p
		info.setKey(key)

		print (addr)
		psw = info.recv()

		if (psw != self.psw):
			c = info.send(b'0')
			print(c)
			self.alert_eavesdroppers(c)
			del self.connections[conn]
			info.key = None
			return False
		else:
			c = info.send(b'1')
			sname, raw = info.recv(include_raw=True)
			self.alert_eavesdroppers(raw)
			info.setName(sname)
			self.send(sname + b" has connected from " + addr[0].encode('utf-8'), None)
			return True



class Client():
	"""
	Class representing the users and/or eavesdroppers
	"""
	def __init__(self, host):
		# establish the connection, then begin the handshack on the client side
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server = s
		s.connect((host, PORT))
		self.connection = Connection(s, host)
		if self.handshake():
			Thread(target=self.sender).start() # only users need the sending thread
		Thread(target=self.reciever).start() # eavesdroppers and users both need the listening thread

	def handshake(self):
		# get the password so we aren't blocking later
		# then do a Diffe-Hellman exchange
		# send the password under encryption
		# then send the password for checking
		# recieve confirmation of if user or eavesdropper, and set up accordingly
		psw = input("What is the server's password? ")
		while len(psw) == 0 or len(psw) > 1000:
			print("The password will be between 1 and 1000 characters long")
			psw = input("What is the server's password? ")

		A = int(self.server.recv(P_LEN).decode('utf-8'))
		r = self.connection.secret
		key = (A**r) % p
		self.server.sendall(bytes(str(self.connection.pubkey), 'utf-8'))
		self.connection.setKey(key)

		self.connection.send(bytes(psw, 'utf-8'))
		response = self.connection.recv()
		if response == b'0':
			print ("Server did not accept that password. Entering in eavesdropper mode.")
			self.connection.key = None
			return False
		else:
			name = input("What name should I display to the server? ")
			self.connection.setName(name)
			self.connection.send(name)
		return True

	def sender(self):
		# Thread function handling sending from the client to the server.
		while True:
			msg = input()
			self.connection.send(msg)
			if (msg == 'exit'):
				return

	def reciever(self):
		# Thread function handling recieving from the server. 
		while True:
			m = self.connection.recv()
			try:
				print(m.decode('utf-8'))
			except Exception as e:
				print(m)



if __name__ == '__main__':
	ip_choice = input("Target server ip (enter nothing if this should be the server instance): ").strip()

	if (ip_choice == ""):
		Server()
	else:
		Client(ip_choice)