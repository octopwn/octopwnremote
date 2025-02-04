import websockets
import asyncio

from octopwnremote.base import OctoPwnRemoteBase

class OctoPwnRemoteClient(OctoPwnRemoteBase):
	def __init__(self, url, timeout=5, debug=False):
		OctoPwnRemoteBase.__init__(self, timeout, debug)
		self.url = url
	
	async def run(self):
		try:
			ws = await websockets.connect(self.url)
			await super().run(ws)
			return True, None
		except Exception as e:
			await self.close()
			return False, e


def main():
	import argparse
	parser = argparse.ArgumentParser(description='OctoPwnRemote Client. Connects to a remote server created by OctoPwn\'s REMOTECONTROL server')
	parser.add_argument('url', help='URL to connect to. Example: ws://localhost:16161')
	parser.add_argument('--debug', help='Enable debug mode', action='store_true')
	args = parser.parse_args()
	
	server = OctoPwnRemoteClient(args.url, debug=args.debug)
	asyncio.run(server.run())

if __name__ == '__main__':
	main()