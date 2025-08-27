"""
Utility functions for the SIEM system.

This module provides various utility functions used throughout the SIEM system.
"""
import os
import sys
import time
import json
import hashlib
import inspect
import asyncio
import functools
import threading
import traceback
from pathlib import Path
from typing import (
    Any, Callable, Dict, List, Optional, Tuple, Union, TypeVar, 
    Awaitable, Type, cast, overload
)
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# Type variable for generic function decorators
F = TypeVar('F', bound=Callable[..., Any])

class Singleton(type):
    """A metaclass that ensures only one instance of a class exists."""
    _instances: Dict[type, 'Singleton'] = {}
    
    def __call__(cls, *args: Any, **kwargs: Any) -> 'Singleton':
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

def get_file_checksum(file_path: Union[str, Path], algorithm: str = 'sha256', 
                    chunk_size: int = 65536) -> str:
    """
    Calculate the checksum of a file.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (default: sha256)
        chunk_size: Size of chunks to read from the file (default: 64KB)
        
    Returns:
        The hexadecimal digest of the file's hash
    """
    file_path = Path(file_path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    hash_func = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def format_bytes(size: float, precision: int = 2) -> str:
    """
    Format bytes to a human-readable string.
    
    Args:
        size: Size in bytes
        precision: Number of decimal places (default: 2)
        
    Returns:
        Formatted string with appropriate unit (B, KB, MB, GB, TB, PB)
    """
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    size = float(size)
    
    for unit in units:
        if abs(size) < 1024.0 or unit == units[-1]:
            return f"{size:.{precision}f} {unit}"
        size /= 1024.0
    
    return f"{size:.{precision}f} B"

def retry(max_attempts: int = 3, delay: float = 1.0, 
         exceptions: Tuple[Type[Exception], ...] = (Exception,),
         backoff: float = 2.0, logger: Optional[logging.Logger] = None) -> Callable[[F], F]:
    """
    Decorator to retry a function on failure with exponential backoff.
    
    Args:
        max_attempts: Maximum number of attempts (default: 3)
        delay: Initial delay between attempts in seconds (default: 1.0)
        exceptions: Tuple of exceptions to catch (default: all exceptions)
        backoff: Backoff multiplier (default: 2.0)
        logger: Optional logger for error messages
        
    Returns:
        Decorated function with retry logic
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            current_delay = delay
            last_exception = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt == max_attempts:
                        if logger:
                            logger.error(
                                f"Failed after {max_attempts} attempts: {str(e)}",
                                exc_info=True
                            )
                        raise
                    
                    if logger:
                        logger.warning(
                            f"Attempt {attempt} failed: {str(e)}. "
                            f"Retrying in {current_delay:.2f}s..."
                        )
                    
                    time.sleep(current_delay)
                    current_delay *= backoff
            
            # This should never be reached due to the raise in the except block
            raise RuntimeError("Unexpected error in retry decorator")
        
        return cast(F, wrapper)
    
    return decorator

class RateLimiter:
    """A simple rate limiter using the token bucket algorithm."""
    
    def __init__(self, rate: float, capacity: int):
        """
        Initialize the rate limiter.
        
        Args:
            rate: Number of tokens to add per second
            capacity: Maximum number of tokens in the bucket
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = threading.Lock()
    
    def _add_tokens(self) -> None:
        """Add tokens based on the elapsed time."""
        now = time.monotonic()
        time_elapsed = now - self.last_update
        self.last_update = now
        
        # Add tokens based on the elapsed time and rate
        self.tokens = min(
            self.capacity,
            self.tokens + time_elapsed * self.rate
        )
    
    def acquire(self, tokens: int = 1) -> bool:
        """
        Try to acquire the specified number of tokens.
        
        Args:
            tokens: Number of tokens to acquire (default: 1)
            
        Returns:
            bool: True if tokens were acquired, False otherwise
        """
        with self._lock:
            self._add_tokens()
            
            if tokens <= self.tokens:
                self.tokens -= tokens
                return True
            return False
    
    async def acquire_async(self, tokens: int = 1) -> bool:
        """
        Asynchronously try to acquire the specified number of tokens.
        
        Args:
            tokens: Number of tokens to acquire (default: 1)
            
        Returns:
            bool: True if tokens were acquired, False otherwise
        """
        return await asyncio.get_event_loop().run_in_executor(
            None, self.acquire, tokens
        )

def parse_timedelta(time_str: str) -> timedelta:
    """
    Parse a time delta string (e.g., '1h30m', '2d', '5m') into a timedelta.
    
    Args:
        time_str: Time delta string (e.g., '1h30m', '2d', '5m')
        
    Returns:
        timedelta: The parsed time delta
        
    Raises:
        ValueError: If the time string is invalid
    """
    if not time_str:
        raise ValueError("Empty time string")
    
    # Parse the time string
    pattern = r'^(\d+d)?(\d+h)?(\d+m)?(\d+s)?$'
    match = re.match(pattern, time_str.lower())
    
    if not match:
        raise ValueError(f"Invalid time string format: {time_str}")
    
    # Extract components
    days = int(match.group(1)[:-1]) if match.group(1) else 0
    hours = int(match.group(2)[:-1]) if match.group(2) else 0
    minutes = int(match.group(3)[:-1]) if match.group(3) else 0
    seconds = int(match.group(4)[:-1]) if match.group(4) else 0
    
    return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)

def get_caller_info(levels_up: int = 1) -> Dict[str, Any]:
    """
    Get information about the caller function.
    
    Args:
        levels_up: Number of stack frames to go up (default: 1 for direct caller)
        
    Returns:
        Dict containing caller information (module, function, line number, etc.)
    """
    frame = inspect.currentframe()
    try:
        # Go up the specified number of frames
        for _ in range(levels_up + 1):
            if frame is None:
                break
            frame = frame.f_back
        
        if frame is None:
            return {}
        
        # Get frame info
        frame_info = inspect.getframeinfo(frame)
        
        return {
            'module': inspect.getmodule(frame).__name__ if inspect.getmodule(frame) else None,
            'function': frame.f_code.co_name,
            'filename': frame_info.filename,
            'lineno': frame_info.lineno,
            'code_context': frame_info.code_context,
            'position': frame_info.positions,
        }
    finally:
        # Avoid reference cycles
        del frame

class Timer:
    """Context manager for timing code blocks."""
    
    def __init__(self, name: str = None, logger: Optional[logging.Logger] = None):
        """
        Initialize the timer.
        
        Args:
            name: Optional name for the timer
            logger: Optional logger to log the timing information
        """
        self.name = name or 'timer'
        self.logger = logger
        self.start_time = None
        self.end_time = None
    
    def __enter__(self) -> 'Timer':
        """Start the timer."""
        self.start_time = time.monotonic()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Stop the timer and log the elapsed time."""
        self.end_time = time.monotonic()
        elapsed = self.elapsed()
        
        if self.logger:
            self.logger.debug(f"{self.name} took {elapsed:.6f} seconds")
    
    def elapsed(self) -> float:
        """Get the elapsed time in seconds."""
        if self.start_time is None:
            return 0.0
        
        end_time = self.end_time or time.monotonic()
        return end_time - self.start_time

def run_in_threadpool(
    func: Callable[..., T],
    *args: Any,
    max_workers: Optional[int] = None,
    **kwargs: Any
) -> T:
    """
    Run a function in a thread pool.
    
    Args:
        func: The function to run
        *args: Positional arguments to pass to the function
        max_workers: Maximum number of worker threads (default: None for default)
        **kwargs: Keyword arguments to pass to the function
        
    Returns:
        The result of the function
    """
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future = executor.submit(func, *args, **kwargs)
        return future.result()

async def run_in_executor(
    func: Callable[..., T],
    *args: Any,
    executor: Optional[ThreadPoolExecutor] = None,
    **kwargs: Any
) -> T:
    """
    Run a function in a thread pool asynchronously.
    
    Args:
        func: The function to run
        *args: Positional arguments to pass to the function
        executor: Optional thread pool executor (default: None for default)
        **kwargs: Keyword arguments to pass to the function
        
    Returns:
        The result of the function
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        executor, 
        functools.partial(func, **kwargs) if kwargs else func,
        *args
    )
