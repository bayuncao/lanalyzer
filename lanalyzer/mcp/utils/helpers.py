#!/usr/bin/env python
"""
Utility functions for MCP server.
"""

from lanalyzer.logger import debug, error


def debug_tool_args(func):
    """Log tool function parameters for debugging"""

    async def wrapper(*args, **kwargs):
        debug(f"Calling tool {func.__name__} with args: {args}, kwargs: {kwargs}")
        try:
            result = await func(*args, **kwargs)
            return result
        except Exception as e:
            error(f"Tool {func.__name__} call failed: {e}")
            import traceback

            error(traceback.format_exc())
            raise

    return wrapper


def generate_client_code_example(host: str, port: int, transport: str = "sse"):
    """
    Generate example code for a Python client to connect to this server.

    Args:
        host: Server host address
        port: Server port
        transport: Transport protocol ("sse" or "streamable-http")

    Returns:
        str: Example Python client code
    """
    if transport == "streamable-http":
        code = f"""
import asyncio
from mcp.client.session import ClientSession
from mcp.client.http import http_client

async def run_client():
    base_url = "http://{host}:{port}"
    print(f"Connecting to {{base_url}}...")
    
    try:
        async with http_client(base_url) as streams:
            print("HTTP connection established")
            read_stream, write_stream = streams
            async with ClientSession(read_stream, write_stream) as session:
                print("ClientSession created, explicitly initializing...")
                
                # IMPORTANT: Explicitly initialize the session to avoid the 
                # "Received request before initialization was complete" error
                max_retries = 3
                retry_delay = 1.0  # seconds
                
                # Try initialization with retries
                for attempt in range(max_retries):
                    try:
                        await session.initialize()
                        print("Session initialized successfully")
                        break
                    except Exception as e:
                        if attempt < max_retries - 1:
                            print(f"Initialization attempt {{attempt+1}} failed: {{e}}")
                            print(f"Retrying in {{retry_delay}} seconds...")
                            await asyncio.sleep(retry_delay)
                            retry_delay *= 1.5  # Exponential backoff
                        else:
                            print(f"All initialization attempts failed: {{e}}")
                            raise
                
                # Now safe to make tool calls
                info = await session.get_server_info()
                print(f"Server info: {{info}}")
                
                # Example tool call:
                # result = await session.call_tool("analyze_file", {{
                #     "file_path": "path/to/your/file.py",
                #     "config_path": "path/to/your/config.json"
                # }})
                # print(f"Analysis result: {{result}}")
                
    except Exception as e:
        print(f"Error: {{e}}")

if __name__ == "__main__":
    asyncio.run(run_client())
"""
    else:  # SSE transport
        code = f"""
import asyncio
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

async def run_client():
    sse_url = "http://{host}:{port}/sse"
    print(f"Connecting to {{sse_url}}...")
    
    try:
        async with sse_client(sse_url) as streams:
            print("SSE connection established")
            read_stream, write_stream = streams
            async with ClientSession(read_stream, write_stream) as session:
                print("ClientSession created, explicitly initializing...")
                
                # IMPORTANT: Explicitly initialize the session to avoid the 
                # "Received request before initialization was complete" error
                max_retries = 3
                retry_delay = 1.0  # seconds
                
                # Try initialization with retries
                for attempt in range(max_retries):
                    try:
                        await session.initialize()
                        print("Session initialized successfully")
                        break
                    except Exception as e:
                        if attempt < max_retries - 1:
                            print(f"Initialization attempt {{attempt+1}} failed: {{e}}")
                            print(f"Retrying in {{retry_delay}} seconds...")
                            await asyncio.sleep(retry_delay)
                            retry_delay *= 1.5  # Exponential backoff
                        else:
                            print(f"All initialization attempts failed: {{e}}")
                            raise
                
                # Now safe to make tool calls
                info = await session.get_server_info()
                print(f"Server info: {{info}}")
                
                # Example tool call:
                # result = await session.call_tool("analyze_file", {{
                #     "file_path": "path/to/your/file.py",
                #     "config_path": "path/to/your/config.json"
                # }})
                # print(f"Analysis result: {{result}}")
                
    except Exception as e:
        print(f"Error: {{e}}")

if __name__ == "__main__":
    asyncio.run(run_client())
"""
    return code
