import traceback
import json
import asyncio

from typing import Dict, List

class OctoPwnRemoteBase:
	def __init__(self, timeout=5, debug=False):
		self.token = 0
		self.timeout = timeout
		self.ws = None
		self.debug = debug
		self._closed = False
		self.__in_task = None
		self.__token_dispatch = {}

	def get_token(self):
		self.token += 1
		return self.token

	async def send(self, data:Dict):
		token = self.get_token()
		self.__token_dispatch[token] = asyncio.Queue()
		data = json.dumps({
			'token': token,
			'command': data
		})
		if self.debug is True:
			print('SRV -> OCTO: ', data)
		
		await self.ws.send(data)
		return token

	async def __handle_in(self):
		try:
			while self._closed is False:
				response_raw = await self.ws.recv()
				if self.debug is True:
					print('OCTO -> SRV: ', response_raw)
				token, response, error = self.decode_response(response_raw)
				if token == 0:
					await self.handle_out_of_band(response, error)
					continue
				
				if error is not None:
					await self.__token_dispatch[token].put((None, error))
					continue
				
				# no higher level error, so we can decode the actual command response
				response, error = self.decode_command_response(response)
				if token not in self.__token_dispatch:
					print('Token not found: %s' % token)
					continue
				await self.__token_dispatch[token].put((response, error))
		except Exception as e:
			traceback.print_exc()
			print('Error: %s' % e)

		finally:
			await self.close()
		
	
	def decode_response(self, response_raw):
		if isinstance(response_raw, bytes):
			response_raw = response_raw.decode()
		try:
			response = json.loads(response_raw)
		except Exception as e:
			return None, e
		token = response.get('token')
		status = response.get('status')
		if status == 'error':
			error = response.get('error')
			return token, None, error
		elif status == 'result':
			return token, response.get('result'), None
		else:
			return token, None, 'Unknown status (response): %s. Raw: %s' % (status, response_raw)

	def decode_command_response(self, response_raw):
		response = json.loads(response_raw)
		status = response.get('status')
		if status == 'error':
			return None, Exception(response.get('error'))
		if status == 'ok':
			return response.get('res'), None
		if status == 'err':
			return None, Exception(response.get('message'))
		else:
			return None, Exception('Unknown status (command): %s Raw: %s' % (status, response_raw))

	async def send_recv(self, data):
		try:
			token = await self.send(data)
			return await asyncio.wait_for(self.__token_dispatch[token].get(), timeout=self.timeout)
		except Exception as e:
			return None, e
		finally:
			del self.__token_dispatch[token]

	async def close(self):
		if self.__in_task is not None:
			self.__in_task.cancel()
		if self.ws is not None:
			await self.ws.close()
		for token in self.__token_dispatch:
			if token == 0:
				continue
			self.__token_dispatch[token].put((None, Exception('Connection closed')))
	
	async def run(self, ws):
		try:
			self.ws = ws
			self.__in_task = asyncio.create_task(self.__handle_in())
			return True, None
		except Exception as e:
			await self.close()
			return False, e

	async def handle_out_of_band(self, response, error):
		if error is not None:
			print('Out of band error: %s' % error)
		else:
			print('Out of band response: %s' % response)
	
	async def get_serverinfo(self):
		cmd = {
				"sessionid": "0",
				"command": "get_serverinfo",
				"args": {}
			}
		return await self.send_recv(cmd)
	
	async def get_proxies(self):
		try:
			cmd = {
				"sessionid": "0",
				"command": "get_proxies",
				"args": {}
			}
			return await self.send_recv(cmd)
		except Exception as e: 
			return None, e
	
	async def get_credentials(self):
		try:
			cmd = {
				"sessionid": "0",
				"command": "get_credentials",
				"args": {}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
		
	async def get_sessions(self):
		try:
			cmd = {
				"sessionid": "0",
				"command": "get_sessions",
				"args": {}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e

	async def create_attack(self, attacktype:str):
		try:
			cmd = {
				"sessionid": "0",
				"command": "create_attack",
				"args": {
					'attacktype': attacktype,
				}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	async def create_util(self, utiltype:str):
		try:
			cmd = {
				"sessionid": "0",
				"command": "create_util",
				"args": {
					'utiltype': utiltype,
				}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	async def create_scanner(self, scannertype:str):
		try:
			cmd = {
				"sessionid": "0",
				"command": "create_scanner",
				"args": {
					'scannertype': scannertype,
				}
			}
			result, err = await self.send_recv(cmd)
			if err is not None:
				raise err
			return result.get('sessionid'), result, None
		except Exception as e:
			return None, None, e
	
	async def get_status(self, sessionid):
		try:
			cmd = {
				"sessionid": sessionid,
				"command": "get_status",
				"args": {}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
		
	async def get_history_entry(self, sessionid, hid, start=0, count=100):
		try:
			cmd = {
				"sessionid": sessionid,
				"command": "get_history_entry",
				"args": {
					'hid': hid,
					'start': start,
					'count': count
				}
			}
			result, err = await self.send_recv(cmd)
			if err is not None:
				raise err
			print(result)
			return result, None
		except Exception as e:
			return None, e
	
	async def get_history_entries(self, sessionid, hid, batchsize=1000):
		try:
			resultscount = None
			res, err = await self.get_scanner_history_list(sessionid)
			if err is not None:
				raise err
			for entry in res:
				if entry['hid'] == hid:
					resultscount = entry['resultscount']
					break
			if resultscount is None:
				raise Exception('History entry not found')
			
			start = 0
			while start < resultscount:
				res, err = await self.get_history_entry(sessionid, hid, start, batchsize)
				if err is not None:
					raise err
				for entry in res:
					yield entry, None
				start += batchsize
			
		except Exception as e:
			yield None, e
	
	async def get_history_list(self, sessionid):
		try:
			cmd = {
				"sessionid": sessionid,
				"command": "get_history_list",
				"args": {}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	async def stop_scanner(self, sessionid):
		try:
			cmd = {
				"sessionid": sessionid,
				"command": "stop",
				"args": {}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	async def start_scanner(self, sessionid):
		try:
			cmd = {
				"sessionid": sessionid,
				"command": "start",
				"args": {}
			}
			result, err = await self.send_recv(cmd)
			if err is not None:
				raise err
			return result.get('hid'), None
		except Exception as e:
			return None, e
	
	async def set_parameters(self, sessionid, paramsdict):
		try:
			cmd = {
				"sessionid": sessionid,
				"command": "set_parameters",
				"args": {
					"argsjson": paramsdict
				}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	async def set_parameter(self, sessionid, paramname, paramvalue):
		try:
			return await self.set_parameters(sessionid, {paramname: paramvalue})
		except Exception as e:
			return None, e
	
	async def get_parameters(self, sessionid):
		try:
			cmd = {
				"sessionid": sessionid,
				"command": "get_parameters",
				"args": {}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e

	async def get_parameter(self, sessionid, paramname):
		try:
			params, err = await self.get_parameters(sessionid)
			if err is not None:
				raise err
			return params.get(paramname), None
		except Exception as e:
			return None, e
	
	async def create_credential_single(self, credentialdict):
		try:
			cmd = {
				"sessionid": "0",
				"command": "create_credential",
				"args": {
					'credjson': credentialdict
				}
			}
			result, err = await self.send_recv(cmd)
			if err is not None:
				raise err
			return result[0], None
		except Exception as e:
			return None, e

	async def create_credential_password(self, username, password, domain=None):
		try:
			cred = {
				'username': username,
				'secret': password,
				'stype': 'password',
				'domain': domain
			}
			return await self.create_credential_single(cred)
		except Exception as e:
			return None, e
	
	async def create_credential_nt(self, username, nthash, domain=None):
		try:
			cred = {
				'username': username,
				'secret': nthash,
				'stype': 'nt',
				'domain': domain
			}
			return await self.create_credential_single(cred)
		except Exception as e:
			return None, e
	
	# TODO: more cred types

	async def create_target_raw(self, targetdict):
		try:
			cmd = {
				"sessionid": "0",
				"command": "create_target",
				"args": {
					'targetjson': targetdict
				}
			}
			result, err =  await self.send_recv(cmd)
			if err is not None:
				raise err
			return result[0], None
		except Exception as e:
			return None, e
		
	async def create_target(self, ip:str=None, hostname:str=None, realm:str = None, domain:str=None):
		try:
			target = {
				'ip': ip,
				'hostname': hostname,
				'realm': realm,
				'domain': domain
			}
			return await self.create_target_raw(target)
		except Exception as e:
			return None, e
	
	async def run_session_command_single(self, sessionid, command:str, args:List[str] = []):
		try:
			cmd = {
				"sessionid": sessionid,
				"command": 'run_session_command',
				"args": {
					'command': command,
					'args': args
				}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
		
	async def get_scanner_history_list(self, sessionid):
		try:
			cmd = {
				"sessionid": sessionid,
				"command": 'get_history_list',
				"args": {}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
		
	async def get_scanner_history_entry(self, sessionid, hid):
		try:
			cmd = {
				"sessionid": sessionid,
				"command": 'get_history_entry',
				"args": {
					'hid': hid
				}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
		
	async def get_targets(self):
		try:
			cmd = {
				"sessionid": "0",
				"command": "get_targets",
				"args": {}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	async def create_client(self, clienttype:str, authtype:str, targetid, credid, proxyid=None, port = None, timeout = None, description = None):
		try:
			cmd = {
				"sessionid": "0",
				"command": "create_client",
				"args": {
					'jsondata': {
						'CTYPE': clienttype,
						'ATYPE': authtype,
						'CID': credid,
						'TID': targetid,
						'PID': proxyid,
						'PORT': port,
						'TIMEOUT': timeout,
						'DESCRIPTION': description
					}
				}
			}
			result, err = await self.send_recv(cmd)
			if err is not None:
				raise err
			return result.get('sessionid'), result, None
		
		except Exception as e:
			return None, None, e
	

	async def get_session_message(self, sessionid, start, count):
		try:
			cmd = {
				"sessionid": "0",
				"command": "get_session_messages",
				"args": {
					'sessionid': sessionid,
					'start': start,
					'count': count
				}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	async def get_session_messages(self, sessionid, start=0, batchsize=1000):
		try:
			while True:
				res, err = await self.get_session_message(sessionid, start, batchsize)
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

	
