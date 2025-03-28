from octopwnremote.client import OctoPwnRemoteClient
from octopwnremote.server import OctoPwnRemoteServer
from octopwnremote.base import OctoPwnRemoteBase
from octopwnremote.utils.processmanager import AsyncProcessManager

import asyncio
import copy
from typing import List, cast
import os
import tempfile

OCTOPWN_HASHCAT_HASHTYPE_LOOKUP = {
	'MD5': '0',
    'NTLM': '1000',
    'NT': '1000',
	'LM': '3000',
	'NETNTLMV2': '5600',
	'NETNTLMV1': '5500',
}

class OctoPwnHashcat:
    def __init__(self, client:OctoPwnRemoteBase, hashcat_path:str = 'hashcat', 
                    hashcat_rules:str = 'best64.rule', hashcat_mask:str = '?a?a?a?a?a?a?a?a', 
                    hashcat_wordlist:str = 'rockyou.txt', maxruntime:int = 300, 
                    crack_existing_credentials:bool = True, watch_new_credentials:bool = True,
                    debug:bool = False, modes:List[str] = ['wordlist', 'bruteforce']):
        self.client = client
        self.hashcat_path = hashcat_path
        self.hashcat_rules = hashcat_rules
        self.hashcat_mask = hashcat_mask
        self.hashcat_wordlist = hashcat_wordlist
        self.maxruntime = maxruntime
        self.crack_existing_credentials = crack_existing_credentials
        self.watch_new_credentials = watch_new_credentials
        self.disconnect_event = asyncio.Event()
        self.debug = debug
        self.modes = modes
        self.__seen_credentials = {}
        self.__autocrack_buffer = {}
        self.__autocrack_task = None

        if self.maxruntime == -1:
            self.maxruntime = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.disconnect()

    async def print(self, *args, **kwargs):
        """Print a message to the console"""
        print(*args, **kwargs)
    
    async def debugprint(self, *args, **kwargs):
        """Print a message to the console if debug is enabled"""
        if self.debug is True:
            print(*args, **kwargs)

    async def print_exc(self, exc:Exception):
        """Print an exception to the console"""
        tb = exc.__traceback__
        await self.print(f"{exc.__class__.__name__}: {str(exc)}")
        while tb is not None:
            await self.print(f"  File \"{tb.tb_frame.f_code.co_filename}\", line {tb.tb_lineno}, in {tb.tb_frame.f_code.co_name}")
            tb = tb.tb_next

    async def run_forever(self):
        """Run the hashcat cracker forever"""
        await self.disconnect_event.wait()

    async def disconnect(self):
        """Disconnect from the client, remove all handlers and cancel the autocrack task"""
        await self.client.unregister_credential_handler(self.autocrack_credential_handler)
        if self.__autocrack_task is not None:
            self.__autocrack_task.cancel()
        self.__autocrack_buffer = {}
        self.__autocrack_task = None
        self.disconnect_event.set()

    async def autocrack_credential_handler(self, cid:int, source_session_id:int):
        """This function will be called from the client when a new credential is added"""
        try:
            await self.debugprint('autocrack_credential_handler: %s' % cid)
            if cid in self.__seen_credentials:
                return True, None
            self.__seen_credentials[int(cid)] = True
            cred, err = await self.client.get_credential(cid)
            if err is not None:
                await self.print(err)
                return False, err
            await self.handle_credential(cred)
            return True, None
        except Exception as e:
            await self.print_exc(e)
            return False, e
    
    async def handle_credential(self, cred:dict):
        """ Fetches the credential data from OctoPwn based on the cid and then cracks it using hashcat """
        try:
            await self.debugprint('handle_credential: %s' % cred)
            credtype = cred.get('stype', '').upper()
            username = cred.get('username', '')
            secret = cred.get('secret', '')
            if credtype not in ['NT', 'KERBEROAST']:
                await self.print(f'Unsupported credtype {credtype}')
                return False, None
            
            if credtype == 'KERBEROAST':
                if username == 'krbtgt':
                    await self.print('Skipping krbtgt user from kerberoasting')
                    return False, None
                #this is a group of different cred types
                if secret.startswith('$krb5tgs$23$'):
                    credtype = '13100'
                elif secret.startswith('$krb5asrep$23$'):
                    credtype = '18200'
                elif secret.startswith('$krb5tgs$17$'):
                    credtype = '19600'
                elif secret.startswith('$krb5tgs$18$'):
                    credtype = '19700'
                elif secret.startswith('$krb5pa$17$'):
                    credtype = '19800'
                elif secret.startswith('$krb5pa$18$'):
                    credtype = '19900'
                else:
                    await self.debugprint('Unsuppoerted credtype %s' % secret[:12])
                    return False, None
                    
            if credtype not in self.__autocrack_buffer:
                self.__autocrack_buffer[credtype] = []
            self.__autocrack_buffer[credtype].append(secret)
            await self.debugprint(f'Added {credtype} hash to autocrack queue')

            if len(self.__autocrack_buffer) > 0 and self.__autocrack_task is None:
                self.__autocrack_task = asyncio.create_task(self.autocrack_worker())
            
            return True, None
        except Exception as e:
            await self.print_exc(e)
            return None, e

    async def autocrack_worker(self):
        """Worker function for autocrack"""
        try:
            # sleeping for 5 seconds to allow for more hashes to be added
            while len(self.__autocrack_buffer) > 0:
                await asyncio.sleep(5)
                buffer = copy.deepcopy(self.__autocrack_buffer)
                self.__autocrack_buffer = {}
                for hashtype in buffer:
                    hhashtype = hashtype
                    try:
                        hhashtype = str(int(hashtype))
                    except:
                        pass
                    for mode in self.modes:
                        await self.hashcat_crack_hashes(
                            hhashtype,
                            buffer[hashtype],
                            mode = mode
                        )
        except Exception as e:
            await self.print_exc(e)
        finally:
            self.__autocrack_task = None

    async def hashcat_crack_hashes(self, hashtype:str, hashes:List[str], mode:str):
        """ Cracks the hashes using hashcat in the given mode mode """
        hashfile = None
        try:
            hashes_upper = {}
            for h in hashes:
                hashes_upper[h.upper()] = h

            hashcatpath = self.hashcat_path
            if hashcatpath is None:
                await self.print('Hashcat path not set. Use sethashcat to set it')
                return False, None

            async def output_handler(is_stderr:bool, line:str):
                if is_stderr is True:
                    await self.print('STDERR: %s' % line)
                    return
                
                if line.find(':') == -1:
                    await self.debugprint('Output is not a result! %s' % line)
                    return
                
                hashstr, pw = line.split(':', 1)
                if hashes_upper.get(hashstr.upper(), None) is None:
                    await self.debugprint('Hash not in hashes! Hashcat ignoring silent mode again?!  %s' % hashstr)
                    return
                hashstr = hashes_upper[hashstr.upper()] #revert to original hash so octopwn can use it
                if pw.startswith('$HEX['):
                    pwbytes = pw[5:-1]
                    for encoding in ['utf-8', 'cp1252', 'latin1']:
                        try:
                            pwbytes = bytes.fromhex(pwbytes).decode(encoding)
                            break
                        except:
                            pass
                    else:
                        await self.print('Could not decode password %s' % pw)
                    pw = pwbytes
                
                await self.print(f'Found password for {hashstr}: {pw}')
                await self.client.put_credential_hash([(hashstr, pw)])
            
            try:
                hashtype = str(int(hashtype))
            except:
                if OCTOPWN_HASHCAT_HASHTYPE_LOOKUP.get(hashtype.upper()) is not None:
                    hashtype = OCTOPWN_HASHCAT_HASHTYPE_LOOKUP[hashtype]
                else:
                    await self.print('Unsupported hash type "%s". Extend the lookup table to support it.' % hashtype)
                    return False, None
            
            
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                for h in hashes:
                    temp_file.write(h + '\n')
                temp_file.flush()
                temp_file.seek(0)
                hashfile = temp_file.name
            
            if mode == 'wordlist':
                await self.hashcat_crack_wordlist(hashtype, hashfile, output_handler)
            elif mode == 'bruteforce':
                await self.hashcat_crack_bruteforce(hashtype, hashfile, output_handler)
            else:
                await self.print('Unsupported mode %s' % mode)
                return False, None
        finally:
            if hashfile is not None:
                os.remove(hashfile)

    async def hashcat_crack_bruteforce(self, hashtype:str, hashfile:List[str], output_handler):
        """ Cracks the hashes using hashcat in bruteforce mode """
        try:
            manager = AsyncProcessManager()

            hashcatcmd = [self.hashcat_path, '--quiet', '-O', '-a', '3', '-m', hashtype, hashfile, self.hashcat_mask]
            if self.hashcat_rules is not None:
                hashcatcmd.extend(['-r', self.hashcat_rules])

            hcmd = ' '.join(hashcatcmd)
            await self.print(f'Running command: {hcmd}')

            pid = await manager.start_process(
                cmd=hashcatcmd,
                on_stdout=output_handler,
            )

            result = None
            try:
                result = await asyncio.wait_for(manager.wait_for_process(pid), timeout=self.maxruntime*60 if self.maxruntime is not None else None)
            except asyncio.TimeoutError:
                await self.print('Timeout reached. Killing process')
                await manager.terminate_process(pid)
                return False, None
            else:
                await self.print(f'Process finished with return code {result}')

        except Exception as e:
            await self.print_exc(e)
            return None, e


    async def hashcat_crack_wordlist(self, hashtype:str, hashfile:List[str], output_handler):
        """ Cracks the hashes using hashcat in wordlist mode """
        try:
            manager = AsyncProcessManager()

            hashcatcmd = [self.hashcat_path, '--quiet', '-O', '-a', '0', '-m', hashtype, hashfile, self.hashcat_wordlist]
            if self.hashcat_rules is not None:
                hashcatcmd.extend(['-r', self.hashcat_rules])

            hcmd = ' '.join(hashcatcmd)
            await self.print(f'Running command: {hcmd}')

            pid = await manager.start_process(
                cmd=hashcatcmd,
                on_stdout=output_handler,
            )

            result = None
            try:
                result = await asyncio.wait_for(manager.wait_for_process(pid), timeout=self.maxruntime*60 if self.maxruntime is not None else None)
            except asyncio.TimeoutError:
                await self.print('Timeout reached. Killing process')
                await manager.terminate_process(pid)
                return False, None
            else:
                await self.print(f'Process finished with return code {result}')

        except Exception as e:
            await self.print_exc(e)
            return None, e

    async def crack_existing(self):
        """ Fetches all credentials from OctoPwn and then cracks them using hashcat """
        creds, err = await self.client.get_credentials()
        if err is not None:
            await self.print(err)
            return
        
        for cid in creds:
            if int(cid) in self.__seen_credentials:
                continue
            self.__seen_credentials[int(cid)] = True
            await self.handle_credential(creds[cid])

    async def run(self):
        """ Main function to run the hashcat cracker """
        try:
            if self.watch_new_credentials is True:
                await self.client.register_credential_handler(self.autocrack_credential_handler)
            if self.crack_existing_credentials is True:
                await self.crack_existing()
        except Exception as e:
            await self.print_exc(e)

async def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--hashcat', type=str, default='hashcat', help='Path to hashcat')
    parser.add_argument('--rules', type=str, default=None, help='Path to hashcat rules')
    parser.add_argument('--mask', type=str, default='?a?a?a?a?a?a?a?a', help='Hashcat mask')
    parser.add_argument('--wordlist', type=str, default='rockyou.txt', help='Path to hashcat wordlist')
    parser.add_argument('--maxruntime', type=int, default=5, help='Max runtime for hashcat (minutes)')
    parser.add_argument('--crack-existing', type=bool, default=True, help='Crack existing credentials')
    parser.add_argument('--watch-new-credentials', type=bool, default=True, help='Watch for new credentials')
    parser.add_argument('--debug', type=bool, default=False, help='Enable debug mode')

    connectionmode_group = parser.add_subparsers(dest='connectionmode', required=True, help='Connection mode')
    client_parser = connectionmode_group.add_parser('client', help='Client mode')
    server_parser = connectionmode_group.add_parser('server', help='Server mode')

    server_parser.add_argument('--host', type=str, default='localhost', help='Host to connect to')
    server_parser.add_argument('--port', type=int, default=16161, help='Port to connect to')
    
    client_parser.add_argument('url', type=str, help='URL to connect to')
    parser.add_argument('modes', type=str, nargs='*', default=['wordlist', 'bruteforce'], help='Modes to run')
    args = parser.parse_args()

    if args.connectionmode == 'server':
        client = OctoPwnRemoteServer(args.host, args.port, debug=args.debug)
    else:
        client = OctoPwnRemoteClient(args.url, debug=args.debug)
    
    _, err = await client.run()
    if err is not None:
        print('Failed to create client/server!')
        print('%s' % err)
        return
    
    async with OctoPwnHashcat(client, hashcat_path=args.hashcat, 
                    hashcat_rules=args.rules, hashcat_mask=args.mask, hashcat_wordlist=args.wordlist, 
                    maxruntime=args.maxruntime, crack_existing_credentials=args.crack_existing, 
                    watch_new_credentials=args.watch_new_credentials, modes=args.modes) as cracker:
        await cracker.run()
        await cracker.run_forever()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())