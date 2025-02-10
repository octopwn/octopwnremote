from octopwnremote.client import OctoPwnRemoteClient
from octopwnremote.server import OctoPwnRemoteServer


### This example is created to demonstate the usage of the OctoPwnRemoteClient / OctoPwnRemoteServer class
### The example requires that OctoPwn is running in the browser and hooked to a GOAD active directory environment


async def test_smbfile(client, cid, targets = '192.168.56.0/24'):
    sid, descriptor, err = await client.create_scanner('smbfile')
    if err is not None:
        print(err)
        return
    
    print('Scanner ID:', sid)

    _, err = await client.set_parameters(sid, 
        {
               'targets': targets,
               'credential': cid
        }
    )
    if err is not None:
        print(err)
        return
    
    params, err = await client.get_parameters(sid)
    if err is not None:
        print(err)
        return
    
    print('Parameters:', params)
    
    hid, err = await client.start_scanner(sid)
    if err is not None:
        print(err)
        return
    
    print('Scanner started! Result:', hid)

    while True:
        status, err = await client.get_status(sid)
        if err is not None:
            print(err)
            return
        
        print('Scanner status:', status)
        if status['running'] is False:
            break

        await asyncio.sleep(5)
    
    print('Scanner finished!')
    historylist, err = await client.get_scanner_history_list(sid)
    if err is not None:
        print(err)
        return
    
    print('Scanner history entries:', historylist)

    async for entry, err in client.get_history_entries(sid, hid):
        if err is not None:
            print(err)
            return
        
        print(entry)



async def main():
    client = OctoPwnRemoteServer('localhost', 16161)
    #client = OctoPwnRemoteClient('ws://localhost:15151')
    _, err = await client.run()
    if err is not None:
        print(err)
        return
    
    res, err = await client.get_file_size('/volatile/octopwn.session')
    if err is not None:
        print(err)
        return
    
    print('File size:', res)

    res, err = await client.read_file_raw('/volatile/octopwn.session', 0, 100)
    if err is not None:
        print(err)
        return
    
    print('File content:', res)
    
    ## Create a credential for user hodor with password hodor
    cid, err = await client.create_credential_password('hodor', 'hodor', 'NORTH')
    if err is not None:
        print(err)
        return
    print('Credential ID:', cid)

    ## Create a target with IP 
    tid, err = await client.create_target('192.168.56.10')
    if err is not None:
        print(err)
        return
    
    print('Target ID:', tid)

    ## lists all credentials
    creds, err = await client.get_credentials()
    if err is not None:
        print(err)
        return
    
    print('Credentials:', creds)


    ## lists all targets
    targets, err = await client.get_targets()
    if err is not None:
        print(err)
        return
    
    print('Targets:', targets)

    ## Creates an SMB connection to the previously created target with the previously created credential
    cid, descriptor, err = await client.create_client(
        'SMB', 
        'NTLM', 
        tid, 
        cid, 
        proxyid= None, 
        port = None, 
        timeout = None, 
        description = None
    )
    if err is not None:
        print(err)
        return
    
    print('Client ID:', cid)
    print('Client descriptor:', descriptor)
    
    ## Uses the creted SMB session to log in to the target server
    res, err = await client.run_session_command_single(cid, 'login')
    if err is not None:
        print(err)
        return
    
    print('Login result:', res)

    if res is False:
        return
    
    ## Lists the shares on the target server
    res, err = await client.run_session_command_single(cid, 'shares')
    if err is not None:
        print(err)
        return
    
    print('shares result:', res)

    ## Prints the console messages from the SMB session
    async for timestamp, message, err in client.get_session_messages(cid):
        if err is not None:
            print(err)
            return
        
        print(message)
        


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())