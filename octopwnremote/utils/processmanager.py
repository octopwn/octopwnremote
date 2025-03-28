import asyncio
import inspect
import locale
import os
import signal
import sys
from asyncio import create_subprocess_exec
from asyncio.subprocess import PIPE
from dataclasses import dataclass
from typing import Dict, List, Optional, Union, Callable, Any, TypeVar, Awaitable


@dataclass
class ProcessResult:
    """Stores the result of a completed process."""
    return_code: int
    stdout: str
    stderr: str
    pid: int


# Type for callbacks that can be either sync or async
T = TypeVar('T')
CallbackType = Callable[[T], Union[Any, Awaitable[Any]]]


def detect_default_encoding():
    """Detect the default encoding based on the operating system."""
    if sys.platform == 'win32':
        # On Windows, command prompt typically uses cp1252 or a specific codepage
        return locale.getpreferredencoding()
    else:
        # On Unix-like systems, UTF-8 is common but check the locale
        return locale.getpreferredencoding() or 'utf-8'


class AsyncProcessManager:
    """Manages asynchronous processes across different platforms."""
    
    def __init__(self, default_encoding: Optional[str] = None):
        self._processes: Dict[int, asyncio.subprocess.Process] = {}
        self._callbacks: Dict[int, List[CallbackType[ProcessResult]]] = {}
        self._stdout_handlers: Dict[int, List[CallbackType[str]]] = {}
        self._results: Dict[int, ProcessResult] = {}
        self._completion_events: Dict[int, asyncio.Event] = {}
        self._encodings: Dict[int, str] = {}
        self._default_encoding = default_encoding or detect_default_encoding()

    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        for pid in self._processes:
            try:
                await self.terminate_process(pid)
            except:
                pass
            
    async def start_process(
        self, 
        cmd: List[str], 
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        on_stdout: Optional[CallbackType[str]] = None,
        on_complete: Optional[CallbackType[ProcessResult]] = None,
        encoding: Optional[str] = None,
    ) -> int:
        """
        Start a new process asynchronously.
        
        Args:
            cmd: Command and arguments to execute
            env: Environment variables for the process
            cwd: Working directory for the process
            on_stdout: Callback for each stdout line (can be async or sync)
            on_complete: Callback when process completes (can be async or sync)
            encoding: Character encoding for process output (auto-detected if None)
            
        Returns:
            Process ID
        """
        process = await create_subprocess_exec(
            *cmd,
            stdout=PIPE,
            stderr=PIPE,
            env=env,
            cwd=cwd
        )
        
        pid = process.pid
        self._processes[pid] = process
        
        # Set encoding for this process
        self._encodings[pid] = encoding or self._default_encoding
        
        # Create completion event for this process
        self._completion_events[pid] = asyncio.Event()
        
        if on_stdout:
            self._stdout_handlers[pid] = [on_stdout]
        else:
            self._stdout_handlers[pid] = []
            
        if on_complete:
            self._callbacks[pid] = [on_complete]
        else:
            self._callbacks[pid] = []
        
        # Start reading stdout and monitoring process
        x = asyncio.create_task(self._read_stdout(pid))
        z = asyncio.create_task(self._read_stderr(pid))
        y = asyncio.create_task(self._monitor_process(pid, x, z))
        
        return pid
    
    async def _execute_callback(self, callback, data):
        """Execute a callback that could be either sync or async."""
        if inspect.iscoroutinefunction(callback):
            # Async callback
            await callback(data)
        else:
            # Sync callback
            callback(data)
    
    async def _read_stdout(self, pid: int) -> None:
        """Read stdout from process line by line and call handlers."""
        try:
            process = self._processes.get(pid)
            if not process:
                return
                
            encoding = self._encodings.get(pid, self._default_encoding)
            
            while True:
                if process is None:
                    return
                line = await process.stdout.readline()
                if not line:
                    break
                try:
                    decoded_line = line.decode(encoding).rstrip()
                except UnicodeDecodeError:
                    # Fallback to latin1 which can decode any byte sequence
                    decoded_line = line.decode('latin1').rstrip()
                
                # Call all registered stdout handlers
                for handler in self._stdout_handlers.get(pid, []):
                    if inspect.iscoroutinefunction(handler):
                        # Async callback
                        await handler(False, decoded_line)
                    else:
                        # Sync callback
                        handler(False, decoded_line)
        except Exception as e:
            import traceback
            traceback.print_exc()

    async def _read_stderr(self, pid: int) -> None:
        """Read stdout from process line by line and call handlers."""
        try:
            process = self._processes.get(pid)
            if not process:
                return
                
            encoding = self._encodings.get(pid, self._default_encoding)
            
            while True:
                if process is None:
                    return
                line = await process.stderr.readline()
                if not line:
                    break
                try:
                    decoded_line = line.decode(encoding).rstrip()
                except UnicodeDecodeError:
                    # Fallback to latin1 which can decode any byte sequence
                    decoded_line = line.decode('latin1').rstrip()
                
                # Call all registered stdout handlers
                for handler in self._stdout_handlers.get(pid, []):
                    if inspect.iscoroutinefunction(handler):
                        # Async callback
                        await handler(True, decoded_line)
                    else:
                        # Sync callback
                        handler(True, decoded_line)
        except Exception as e:
            import traceback
            traceback.print_exc()
        
    async def _monitor_process(self, pid: int, stdout_read_task, stderr_read_task) -> None:
        """Monitor process for completion and store result."""
        process = self._processes.get(pid)
        if not process:
            return
            
        encoding = self._encodings.get(pid, self._default_encoding)
        
        try:
            # If no stdout handlers, wait for process to complete
            stdout_str = ''
            stderr_str = ''
            if len(self._stdout_handlers.get(pid, [])) == 0:
                stdout, stderr = await process.communicate()
                # Decode with specified encoding
                try:
                    stdout_str = stdout.decode(encoding)
                    stderr_str = stderr.decode(encoding)
                except UnicodeDecodeError:
                    # Fallback to latin1 which can decode any byte sequence
                    stdout_str = stdout.decode('latin1')
                    stderr_str = stderr.decode('latin1')
            
            return_code = await process.wait()

            # Wait for stdout reader to complete
            await stdout_read_task
            await stderr_read_task
            
            # Store the result
            result = ProcessResult(
                return_code=return_code,
                stdout=stdout_str,
                stderr=stderr_str,
                pid=pid
            )
            self._results[pid] = result
            
            # Call completion callbacks
            for callback in self._callbacks.get(pid, []):
                await self._execute_callback(callback, result)
                
        except Exception as e:
            import traceback
            traceback.print_exc()
            # If there's an error, store it in the result
            result = ProcessResult(
                return_code=-1,
                stdout="",
                stderr=f"Error monitoring process: {str(e)}",
                pid=pid
            )
            self._results[pid] = result
        finally:
            # Clean up process resources
            if pid in self._processes:
                del self._processes[pid]
            if pid in self._encodings:
                del self._encodings[pid]
                
            # Set completion event regardless of success or failure
            completion_event = self._completion_events.get(pid)
            if completion_event:
                completion_event.set()
    
    async def terminate_process(self, pid: int) -> bool:
        """Gracefully terminate a process."""
        process = self._processes.get(pid)
        if not process:
            return False
            
        if sys.platform == 'win32':
            # Windows doesn't support SIGTERM
            process.terminate()
        else:
            # Send SIGTERM on Unix platforms
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                return False
                
        return True
    
    async def kill_process(self, pid: int) -> bool:
        """Forcefully kill a process."""
        process = self._processes.get(pid)
        if not process:
            return False
            
        process.kill()
        return True
    
    async def get_result(self, pid: int) -> Optional[ProcessResult]:
        """Get the result of a completed process."""
        return self._results.get(pid)
    
    async def is_running(self, pid: int) -> bool:
        """Check if a process is still running."""
        return pid in self._processes
    
    async def wait_for_process(self, pid: int) -> Optional[ProcessResult]:
        """Wait for a process to complete and return its result."""
        # If process already completed, return result immediately
        if pid in self._results:
            return self._results.get(pid)
            
        # If process unknown, return None
        if pid not in self._processes and pid not in self._completion_events:
            return None
            
        # Wait for completion event
        completion_event = self._completion_events.get(pid)
        if completion_event:
            await completion_event.wait()
            
        # Return the result
        return self._results.get(pid)
    
    async def list_processes(self) -> List[int]:
        """Get list of all managed process IDs."""
        return list(self._processes.keys())


# Example usage
async def example():
    # Create process manager
    manager = AsyncProcessManager()
    
    # Example of asynchronous stdout handler
    async def async_stdout_handler(is_stderr, line):
        print(f"Async handler: {line}")
    
    # Example of asynchronous completion handler
    async def async_completion_handler(result):
        print(f"Async completion: Exit code {result.return_code}")
    
    # Start a process with specific encoding and mix of sync/async handlers
    pid = await manager.start_process(
        cmd=["ls", "-la"] if sys.platform != "win32" else ["dir"],
        on_stdout=async_stdout_handler,
        on_complete=async_completion_handler,
        #encoding="utf-8"  # Explicitly set encoding
    )

    print(f"Started process with PID: {pid}")
    
    # Wait for process to complete
    result = await manager.wait_for_process(pid)
    
    print(f"Process output:\n{result.stdout}")
    
    
if __name__ == "__main__":
    asyncio.run(example())