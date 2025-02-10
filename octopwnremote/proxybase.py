import socket
import json

from typing import Dict, List

# this is terrible, but it's just a PoC

class OctoPwnRemoteBlockingBase:
	def __init__(self, ip = 'localhost', port = 16162, timeout=5):
		self.timeout = timeout
		self.ip = ip
		self.port = port

	def send_recv(self, cmd):
		try:
			with socket.create_connection((self.ip, self.port)) as sock:
				data = json.dumps(cmd).encode() + b'\n'
				sock.sendall(data)
				# read line
				received_data = b''
				while True:
					chunk = sock.recv(40960)
					if not chunk:  # No more data, connection closed by the server
						break
					received_data += chunk
					if received_data.find(b'\n') != -1:
						break
				return json.loads(received_data.decode()), None
		except Exception as e:
			return None, e
	
	def get_serverinfo(self):
		cmd = {
				"command": "get_serverinfo",
				"args": []
			}
		return self.send_recv(cmd)
	
	def get_proxies(self):
		try:
			cmd = {
				"command": "get_proxies",
				"args": []
			}
			return self.send_recv(cmd)
		except Exception as e: 
			return None, e
	
	def get_credentials(self):
		"""
		Returns a list of all the credentials available on the OctoPwn instance.

		Args:
			None
		"""
		try:
			cmd = {
				"command": "get_credentials",
				"args": []
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
		
	def get_sessions(self):
		"""
		Returns a list of all the sessions available on the OctoPwn instance.

		Args:
			None
		"""
		try:
			cmd = {
				"command": "get_sessions",
				"args": []
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e

	def create_attack(self, attacktype:str):
		"""
		Creates an attack object on the OctoPwn instance. Returns the sessionid of the created attack object.
		Attack objects are used to perform various attacks on targets.
		Creating the attack object does not start the attack, it just creates the object.

		Args:
			attacktype (str): The type of attack to create. This should be one of the attack types available on the OctoPwn instance.

		"""
		try:
			cmd = {
				"command": "create_attack",
				"args": [
					attacktype,
				]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	def create_util(self, utiltype:str):
		"""
		Creates a utility object on the OctoPwn instance. Returns the sessionid of the created utility object.
		Utility objects are used to perform various utility functions on targets.
		Creating the utility object does not start the utility, it just creates the object.

		Args:
			utiltype (str): The type of utility to create. This should be one of the utility types available on the OctoPwn instance.
		"""
		try:
			cmd = {
				"command": "create_util",
				"args": [
					utiltype,
				]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	def create_scanner(self, scannertype:str):
		"""
		Creates a scanner object on the OctoPwn instance. Returns the sessionid of the created scanner object.
		Scanner objects are used to perform various scanning functions on targets.
		Creating the scanner object does not start the scan, it just creates the object.

		Args:
			scannertype (str): The type of scanner to create. This should be one of the scanner types available on the OctoPwn instance.
		"""
		try:
			cmd = {
				"command": "create_scanner",
				"args": [
					scannertype,
				]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, None, e
	
	def get_status(self, sessionid:int):
		"""
		Returns the status of the session with the given sessionid.
		Used to check wether an attack, utility or scanner is actively performing an action.

		Args:
			sessionid (int): The sessionid of the session to get the status of.
		"""
		try:
			cmd = {
				"command": "get_status",
				"args": [sessionid]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
		
	def get_history_entry(self, sessionid:int, hid:int, start:int=0, count:int=100):
		
		try:
			cmd = {
				"sessionid": sessionid,
				"command": "get_history_entry",
				"args": [
					sessionid,
					hid,
					start,
					count
				]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	def get_history_list(self, sessionid):
		try:
			cmd = {
				"command": "get_history_list",
				"args": [sessionid]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	def stop_scanner(self, sessionid):
		try:
			cmd = {
				"command": "stop_scanner",
				"args": [sessionid]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	def start_scanner(self, sessionid):
		try:
			cmd = {
				"command": "start_scanner",
				"args": [sessionid]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	def set_parameters(self, sessionid, paramsdict):
		try:
			cmd = {
				"command": "set_parameters",
				"args": [sessionid, paramsdict]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	def set_parameter(self, sessionid, paramname, paramvalue):
		try:
			return self.set_parameters(sessionid, {paramname: paramvalue})
		except Exception as e:
			return None, e
	
	def get_parameters(self, sessionid):
		try:
			cmd = {
				"command": "get_parameters",
				"args": [sessionid]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e

	def get_parameter(self, sessionid, paramname):
		try:
			params, err = self.get_parameters(sessionid)
			if err is not None:
				raise err
			return params.get(paramname), None
		except Exception as e:
			return None, e
	
	def create_credential_single(self, credentialdict):
		try:
			cmd = {
				"command": "create_credential_single",
				"args": [
					credentialdict
				]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e

	def create_credential_password(self, username, password, domain=None):
		try:
			cred = {
				'username': username,
				'secret': password,
				'stype': 'password',
				'domain': domain
			}
			return self.create_credential_single(cred)
		except Exception as e:
			return None, e
	
	def create_credential_nt(self, username, nthash, domain=None):
		try:
			cred = {
				'username': username,
				'secret': nthash,
				'stype': 'nt',
				'domain': domain
			}
			return self.create_credential_single(cred)
		except Exception as e:
			return None, e
	
	# TODO: more cred types

	def create_target_raw(self, targetdict):
		try:
			cmd = {
				"command": "create_target_raw",
				"args": [
					targetdict
				]
			}
			result, err =  self.send_recv(cmd)
			if err is not None:
				raise err
			return result, None
		except Exception as e:
			return None, e
		
	def create_target(self, ip:str=None, hostname:str=None, realm:str = None, dcip:str=None):
		try:
			target = {
				'ip': ip,
				'hostname': hostname,
				'realm': realm,
				'dcip': dcip
			}
			return self.create_target_raw(target)
		except Exception as e:
			return None, e
	
	def run_session_command_single(self, sessionid, command:str, args:List[str] = []):
		try:
			cmd = {
				"command": 'run_session_command_single',
				"args": [
					sessionid,
					command,
					args
				]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
		
	def get_scanner_history_list(self, sessionid):
		try:
			cmd = {
				"command": 'get_history_list',
				"args": [sessionid]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
		
	def get_scanner_history_entry(self, sessionid, hid):
		try:
			cmd = {
				"command": 'get_history_entry',
				"args": [
					sessionid,
					hid
				]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
		
	def get_targets(self):
		try:
			cmd = {
				"command": "get_targets",
				"args": []
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	def create_client(self, clienttype:str, authtype:str, targetid, credid, proxyid=None, port = None, timeout = None, description = None):
		try:
			cmd = {
				"command": "create_client",
				"args": [
					clienttype,
					authtype,
					targetid,
					credid,
					proxyid,
					port,
					timeout,
					description
				]
			}
			result, err = self.send_recv(cmd)
			if err is not None:
				raise err
			return result, None
		
		except Exception as e:
			return None, None, e
	

	def get_session_message(self, sessionid, start, count):
		try:
			cmd = {
				
				"command": "get_session_messages",
				"args": [
					sessionid,
					start,
					count
				]
			}
			return self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	def get_session_messages(self, sessionid, start=0, batchsize=1000):
		try:
			while True:
				res, err = self.get_session_message(sessionid, start, batchsize)
				if err is not None:
					raise err
				if len(res) == 0:
					break
				for entry in res:
					timestamp, message = entry
					yield timestamp, message, None
				start += batchsize
		except Exception as e:
			yield None, None, e

		
	def read_file_raw(self, path:str, offset:int, size:int):
		try:
			cmd = {
				"sessionid": "0",
				"command": "read_file_raw",
				"args": [
					path,
					offset,
					size
				]
			}
			result, err = self.send_recv(cmd)
			if err is not None:
				raise err
			return result, None
		except Exception as e:
			return None, e
	
	def get_file_size(self, path:str):
		try:
			res, err = self.read_file_raw(path, 0, 0)
			if err is not None:
				raise err
			if 'error' in res and res['error'] is not None:
				raise Exception(res['error'])
			return res['result']['total'], None
		except Exception as e:
			return None, e
	
	def read_file(self, path:str, offset:int, size:int):
		try:
			res, err = self.read_file_raw(path, offset, size)
			if err is not None:
				raise err
			if 'error' in res and res['error'] is not None:
				raise Exception(res['error'])
			return bytes.fromhex(res['result']['data']), None
		except Exception as e:
			return None, e
	
	def download_file(self, path:str, localpath:str, batchsize=40960):
		try:
			size, err = self.get_file_size(path)
			if err is not None:
				raise err
			offset = 0
			with open(localpath, 'wb') as f:
				while offset < size:
					data, err = self.read_file(path, offset, batchsize)
					if err is not None:
						raise err
					f.write(data)
					offset += len(data)
			return True, None
		except Exception as e:
			return None, e

def main():
	pb = OctoPwnRemoteBlockingBase()
	#print(pb.get_proxies())
	#print(pb.get_credentials())
	#print(pb.get_sessions())
	#print(pb.create_scanner('portscan'))
	#print(pb.create_credential_password('test', 'test2'))
	#print(pb.get_parameters(2))
	print(pb.get_scanner_history_entry(27, 0))
	
if __name__ == '__main__':
	main()