import traceback
import json
import asyncio
from typing import Dict, List, Tuple

class OctoPwnRemoteBase:
	def __init__(self, timeout=10, debug=False):
		self.token = 0
		self.timeout = 10#timeout
		self.ws = None
		self.debug = debug
		self._closed = False
		self.__in_task = None
		self.__token_dispatch = {}
		self.__new_credential_callbacks = []
		self.__new_session_callbacks = []
		self.__new_target_callbacks = []

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
					rlen = len(response_raw)
					print('OCTO -> SRV: ', rlen if rlen > 1024 else response_raw)
				token, response, error = self.decode_response(response_raw)
				if token == 0:
					x = asyncio.create_task(self.handle_out_of_band(response, error))
					continue
				
				if error is not None:
					await self.__token_dispatch[token].put((None, error))
					continue
				
				# no higher level error, so we can decode the actual command response
				response, error = self.decode_command_response(response)
				if token not in self.__token_dispatch:
					print('Token not found: %s' % token)
					print('current token dispatch: %s' % self.__token_dispatch)
					continue
				await self.__token_dispatch[token].put((response, error))
		except Exception as e:
			print('Internal message handler error. Connection will be closed.')
			traceback.print_exc()

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
		"""Used for commands that return a single response (result or error)"""
		try:
			token = await self.send(data)
			return await asyncio.wait_for(self.__token_dispatch[token].get(), timeout=self.timeout)
		except Exception as e:
			return None, e
		finally:
			if token in self.__token_dispatch:
				del self.__token_dispatch[token]

	async def close(self):
		"""Closes the connection and cancels the in_task"""
		if self.__in_task is not None:
			self.__in_task.cancel()
		if self.ws is not None:
			await self.ws.close()
		for token in self.__token_dispatch:
			if token == 0:
				continue
			self.__token_dispatch[token].put((None, Exception('Connection closed')))
	
	async def run(self, ws):
		"""Always call this first to start the incoming message handler"""
		try:
			self.ws = ws
			self.__in_task = asyncio.create_task(self.__handle_in())
			return True, None
		except Exception as e:
			await self.close()
			return False, e

	async def handle_out_of_band(self, response, error):
		"""Handles out of band messages (new credential, new target, new session)"""
		if error is not None:
			print('Out of band error: %s' % error)
		else:
			if response.get('type') == 'credential':
				await self.handle_new_credential(response.get('cid'), response.get('source_session_id'))
			elif response.get('type') == 'target':
				await self.handle_new_target(response.get('tid'), response.get('source_session_id'))
			elif response.get('type') == 'session':
				await self.handle_new_session(response.get('sid'), response.get('source_session_id'))
			else:
				print('Unhandled out of band response: %s' % response)

	async def register_credential_handler(self, callback):
		"""Register a callback to handle new credentials"""
		self.__new_credential_callbacks.append(callback)

	async def register_session_handler(self, callback):
		"""Register a callback to handle new sessions"""
		self.__new_session_callbacks.append(callback)
	
	async def register_target_handler(self, callback):
		"""Register a callback to handle new targets"""
		self.__new_target_callbacks.append(callback)
	
	async def unregister_credential_handler(self, callback):
		"""Unregister a callback to handle new credentials"""
		self.__new_credential_callbacks.remove(callback)

	async def unregister_session_handler(self, callback):
		"""Unregister a callback to handle new sessions"""
		self.__new_session_callbacks.remove(callback)
	
	async def unregister_target_handler(self, callback):
		"""Unregister a callback to handle new targets"""
		self.__new_target_callbacks.remove(callback)
	
	async def handle_new_credential(self, cid:int, source_session_id:int):
		"""Default handler for new credentials"""
		try:
			if len(self.__new_credential_callbacks) == 0:
				print(f'New credential created: {cid} from session {source_session_id}')
				print('Register a callback to handle the new credential')
				return
			
			for callback in self.__new_credential_callbacks:
				await callback(cid, source_session_id)
		except Exception as e:
			print('Error handling new credential: %s' % e)
	
	async def handle_new_session(self, sid:int, source_session_id:int):
		"""Default handler for new sessions"""
		try:
			if len(self.__new_session_callbacks) == 0:
				print(f'New session created: {sid} from session {source_session_id}')
				print('Register a callback to handle the new session')
				return
			
			for callback in self.__new_session_callbacks:
				await callback(sid, source_session_id)
		except Exception as e:
			print('Error handling new session: %s' % e)

	async def handle_new_target(self, tid:int, source_session_id:int):
		"""Default handler for new targets"""
		try:
			if len(self.__new_target_callbacks) == 0:
				print(f'New target created: {tid} from session {source_session_id}')
				print('Register a callback to handle the new target')
				return
			
			for callback in self.__new_target_callbacks:
				await callback(tid, source_session_id)
		except Exception as e:
			print('Error handling new target: %s' % e)
	
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

	async def get_credential(self, cid:int):
		try:
			cmd = {
				"sessionid": "0",
				"command": "get_credential",
				"args": {
					"cid": cid
				}
			}
			res, err = await self.send_recv(cmd)
			if err is not None:
				raise err
			return res, None
		except Exception as e:
			return None, e

	async def put_credential_hash(self, hashpw:List[Tuple[str,str]]):
		try:
			cmd = {
				"sessionid": "0",
				"command": "put_credential_hash",
				"args": {
					"hashpw": hashpw
				}
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
		
	async def create_target(self, ip:str=None, hostname:str=None, realm:str = None, dcip:str=None):
		try:
			target = {
				'ip': ip,
				'hostname': hostname,
				'realm': realm,
				'dcip': dcip
			}
			return await self.create_target_raw(target)
		except Exception as e:
			return None, e
	
	async def run_session_command_single(self, sessionid, command:str, args:List[str] = []):
		try:
			# correcting the args
			# most args are taken as strings
			finalargs = []
			for arg in args:
				if isinstance(arg, bool):
					finalargs.append('0' if arg is False else '1')
					continue
				finalargs.append(arg)
			
			cmd = {
				"sessionid": sessionid,
				"command": 'run_session_command',
				"args": {
					'command': command,
					'args': finalargs
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

	async def read_file_raw(self, path:str, offset:int, size:int):
		try:
			cmd = {
				"sessionid": "0",
				"command": "read_file",
				"args": {
					'path': path,
					'offset': offset,
					'size': size
				}
			}
			return await self.send_recv(cmd)
		except Exception as e:
			return None, e
	
	async def get_file_size(self, path:str):
		try:
			return await self.read_file_raw(path, 0, 0)
		except Exception as e:
			return None, e

	async def read_file_full(self, path:str, batchsize=10240):
		try:
			total, err = await self.get_file_size(path)
			if err is not None:
				raise err
			
			start = 0
			while start < total:
				res, err = await self.read_file_raw(path, start, batchsize)
				if err is not None:
					raise err
				yield res['data'], None
				start += batchsize
			
		except Exception as e:
			yield None, e