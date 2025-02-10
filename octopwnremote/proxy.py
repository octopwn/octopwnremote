import json
import asyncio

from typing import Dict, List

from octopwnremote.server import OctoPwnRemoteServer

class OctoPwnRemoteProxy:
	def __init__(self, listen_ip:str='localhost', listen_port:int = 16162, remote_server_ip='localhost', remote_server_port:int= 16161, timeout=5): # if someone wants to use client it's not supported
		self.listen_ip = listen_ip
		self.listen_port = listen_port
		self.remote_server_ip = remote_server_ip
		self.remote_server_port = remote_server_port
		self.client = None
		self.tcpserver = None
		self.tcpserver_task = None
		self.commslock = None

	async def close(self):
		if self.client is not None:
			await self.client.close()
			self.client = None
		if self.tcpserver is not None:
			self.tcpserver.close()
			await self.tcpserver.wait_closed()
			self.tcpserver = None
		if self.tcpserver_task is not None:
			self.tcpserver_task.cancel()
			self.tcpserver_task = None

	async def handle_client(self, reader, writer):
		try:
			if self.client is None:
				print('Client not connected, dropping connection')
				writer.close()
				return
			while True:
				async with self.commslock:
					data = await reader.readline()
					if data is None or len(data) == 0:
						return
					
					data = data.decode().strip()
					print('AI -> PROXY: ', repr(data))
					json_data = json.loads(data)
					command = json_data['command']
					args = json_data['args']

					# dynamically invoke the command on the client
					t = await getattr(self.client, command)(*args)
					if len(t) == 2:
						result, err = t
					else:
						_, result, err = t
					resdata = {
						'result': result,
						'error': str(err) if err is not None else None
					}
					#print('Result:', resdata)
					print('PROXY -> AI: "%s" (%s)', (command, len(str(resdata))))
					writer.write(json.dumps(resdata).encode()+b'\n')

					print('============================================\n\n')


		except Exception as e:
			print('Error:', e)
			resdata = {
				'result': None,
				'error': str(e)
			}
			writer.write(json.dumps(resdata).encode()+b'\n')
		return
	
	async def run(self):
		try:
			self.commslock = asyncio.Lock()
			self.client = OctoPwnRemoteServer(self.remote_server_ip, self.remote_server_port, debug=True)
			_, err = await self.client.run()
			if err is not None:
				print(err)
				return
			
			self.tcpserver = await asyncio.start_server(self.handle_client, self.listen_ip, self.listen_port)
			await self.tcpserver.serve_forever()

			return True, None
		except Exception as e:
			await self.close()
			return False, e


def main():
	import argparse
	parser = argparse.ArgumentParser(description='OctoPwnRemote Proxy. Used as a bridge between non-asynchronous clients and the OctoPwnRemoteServer')
	parser.add_argument('--ip', default='localhost', help='IP address to listen on')
	parser.add_argument('--port', default=16162, type=int, help='Port to listen on')
	parser.add_argument('--remote-ip', default='localhost', help='IP address of the OctoPwnRemoteServer')
	parser.add_argument('--remote-port', default=16161, type=int, help='Port of the OctoPwnRemoteServer')
	parser.add_argument('--debug', help='Enable debug mode', action='store_true')
	args = parser.parse_args()
	
	proxy = OctoPwnRemoteProxy()
	asyncio.run(proxy.run())

if __name__ == '__main__':
	main()