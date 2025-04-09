from octopwnremote.server import OctoPwnRemoteServer
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import dataclass

from mcp.server.fastmcp import Context, FastMCP


@dataclass
class OctoPwnContext:
    client: object


mcp = FastMCP("OctoPwn")


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[OctoPwnContext]:
    """Manage application lifecycle with type-safe context"""
    # Initialize on startup
    client = OctoPwnRemoteServer('localhost', 16161)
    #client = OctoPwnRemoteClient('ws://localhost:15151')
    
    try:
        _, err = await client.run()
        if err is not None:
            raise err
        yield OctoPwnContext(client=client)
    finally:
        # Cleanup on shutdown
        await client.close()

@mcp.tool()
async def list_credentials(ctx: OctoPwnContext) -> str:
    """List all credentials"""
   
    res, err = await ctx.client.get_credentials()
    if err is not None:
        raise err
    return res
