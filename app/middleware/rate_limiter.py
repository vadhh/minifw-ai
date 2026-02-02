"""
Rate Limiter Middleware for Login Endpoint
Implements Token Bucket algorithm for fail-closed security
"""
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, Tuple
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse


class TokenBucketRateLimiter:
    """
    Token Bucket Rate Limiter
    
    Implements a per-IP token bucket algorithm for rate limiting.
    - Each IP gets a bucket with a maximum capacity
    - Tokens refill at a constant rate
    - Requests consume tokens
    - If no tokens available, request is rejected
    
    Attributes:
        max_requests: Maximum number of requests allowed in the time window
        time_window: Time window in seconds
        buckets: Dictionary mapping IP addresses to (token_count, last_refill_time)
        lock: Thread lock for thread-safe operations
    """
    
    def __init__(self, max_requests: int = 5, time_window: int = 60):
        """
        Initialize rate limiter
        
        Args:
            max_requests: Maximum requests allowed per time window (default: 5)
            time_window: Time window in seconds (default: 60)
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.buckets: Dict[str, Tuple[float, float]] = defaultdict(lambda: (float(max_requests), time.time()))
        self.lock = Lock()
    
    def _refill_bucket(self, ip: str) -> Tuple[float, float]:
        """
        Refill tokens for an IP address based on elapsed time
        
        Args:
            ip: IP address
            
        Returns:
            Tuple of (current_tokens, last_refill_time)
        """
        tokens, last_refill = self.buckets[ip]
        now = time.time()
        elapsed = now - last_refill
        
        # Calculate tokens to add based on elapsed time
        # Tokens refill at rate of max_requests / time_window per second
        refill_rate = self.max_requests / self.time_window
        new_tokens = min(self.max_requests, tokens + (elapsed * refill_rate))
        
        return (new_tokens, now)
    
    def is_allowed(self, ip: str) -> Tuple[bool, int]:
        """
        Check if request from IP is allowed
        
        Args:
            ip: IP address to check
            
        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        with self.lock:
            # Refill bucket
            tokens, last_refill = self._refill_bucket(ip)
            
            if tokens >= 1.0:
                # Allow request and consume token
                self.buckets[ip] = (tokens - 1.0, last_refill)
                return (True, 0)
            else:
                # Rate limit exceeded - calculate retry after
                refill_rate = self.max_requests / self.time_window
                time_to_next_token = (1.0 - tokens) / refill_rate
                retry_after = int(time_to_next_token) + 1
                return (False, retry_after)
    
    def cleanup_old_entries(self, max_age: int = 3600):
        """
        Remove old entries to prevent memory bloat
        Should be called periodically
        
        Args:
            max_age: Maximum age in seconds before entry is removed
        """
        with self.lock:
            now = time.time()
            old_ips = [
                ip for ip, (_, last_refill) in self.buckets.items()
                if now - last_refill > max_age
            ]
            for ip in old_ips:
                del self.buckets[ip]


# Global rate limiter instance for login endpoint
# 5 failed attempts per minute per IP
login_rate_limiter = TokenBucketRateLimiter(max_requests=5, time_window=60)


def get_client_ip(request: Request) -> str:
    """
    Extract client IP address from request
    
    Checks X-Forwarded-For header first (for proxy/load balancer scenarios),
    then falls back to direct client address
    
    Args:
        request: FastAPI request object
        
    Returns:
        Client IP address as string
    """
    # Check X-Forwarded-For header (for proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take first IP in chain (actual client)
        return forwarded_for.split(",")[0].strip()
    
    # Fallback to direct client
    if request.client:
        return request.client.host
    
    return "unknown"


def check_rate_limit(request: Request):
    """
    Dependency function to check rate limit for login endpoint
    
    Args:
        request: FastAPI request object
        
    Raises:
        HTTPException: 429 if rate limit exceeded
    """
    client_ip = get_client_ip(request)
    allowed, retry_after = login_rate_limiter.is_allowed(client_ip)
    
    if not allowed:
        # Rate limit exceeded - return 429 with Retry-After header
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later.",
            headers={"Retry-After": str(retry_after)}
        )
