import websockets
import asyncio

from octopwnremote.base import OctoPwnRemoteBase

"""
This class will wait for an incoming connection from OctoPwn's REMOTECONTROLJS module,
and will immedaitely return from the `run` function once the connection is established.

You must use this class inside your code that does the actual work, as this class
only handles the connection and the initial setup.
See the `proxy.py` file for an example on how to use this class.
"""

class OctoPwnRemoteServer(OctoPwnRemoteBase):
	def __init__(self, listen_ip='localhost', listen_port:int=16161, timeout=5, debug=False):
		OctoPwnRemoteBase.__init__(self, timeout=timeout, debug=debug)
		self.listen_ip = listen_ip
		self.listen_port = listen_port
		self.server = None
		self.server_task = None
		self.client_connected_evt = None
		
	async def handle_client(self, ws):
		try:
			if self.client_connected_evt.is_set():
				print('[OctoPwnRemoteServer] Handler already connected, dropping connection!')
				await ws.close()
				return
			
			await super().run(ws)
			self.client_connected_evt.set()
			await ws.wait_closed()

		except Exception as e:
			await self.close()
			return False, e
		return True, None
	
	async def run(self):
		try:
			self.client_connected_evt = asyncio.Event()
			self.server = await websockets.serve(self.handle_client, self.listen_ip, self.listen_port)
			self.server_task = asyncio.create_task(self.server.serve_forever())
			print('[OctoPwnRemoteServer] Server started on ws://{}:{}'.format(self.listen_ip, self.listen_port))
			print('[OctoPwnRemoteServer] Waiting for OctoPwn handler to connect...')
			await self.client_connected_evt.wait()
			print('[OctoPwnRemoteServer] OctoPwn hanlder connected!')
			return True, None
		except Exception as e:
			await self.close()
			return False, e

def main():
	import argparse
	parser = argparse.ArgumentParser(description='OctoPwnRemote Server. Waits for connections from OctoPwn\'s REMOTECONTROLJS module')
	parser.add_argument('--ip', default='localhost', help='IP address to listen on')
	parser.add_argument('--port', default=16161, type=int, help='Port to listen on')
	parser.add_argument('--debug', help='Enable debug mode', action='store_true')
	args = parser.parse_args()
	
	server = OctoPwnRemoteServer(args.ip, args.port, debug=args.debug)
	asyncio.run(server.run())

if __name__ == '__main__':
	main()