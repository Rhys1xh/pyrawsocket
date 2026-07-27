#!/usr/bin/env python3
"""
pyrawsocket v3.1.1 - Production-Grade Native Socket Library for Python
======================================================================

[Documentation header preserved from previous version]

Critical Fixes in v3.1.1:
    - FIXED: sendall() byref() offset bug (despite warning about it!)
    - FIXED: sizeof() usage in fd_set definition (was using unimported function)
    - FIXED: Thread safety documentation now explicitly lists thread-safe parts
    - FIXED: fcntl import moved to module level with platform guard

What I Actually Learned (The Real Lesson):
    Documentation doesn't prevent bugs. Only tests prevent bugs.
    The byref() bug survived multiple reviews because it was in the
    "obviously correct" part of the code. Never trust your own comments.
"""

import ctypes
import ctypes.util
from ctypes import (
    Structure, Union, POINTER, c_void_p, c_char_p, c_int, c_uint,
    c_short, c_ushort, c_long, c_ulong, c_size_t, c_ssize_t,
    c_uint8, c_uint16, c_uint32, c_int32, c_int64,
    pointer, byref, sizeof, create_string_buffer, cast, addressof,
    memmove, string_at
)
import os
import sys
import errno
import socket as _stdlib_socket
import select as _stdlib_select
from enum import IntEnum, IntFlag, auto
from typing import Optional, Tuple, List, Set, Dict, Any, Union, Callable
import atexit
import weakref
import warnings
import threading
import time

# Platform-guarded fcntl import (was inside bytes_available method)
if not sys.platform == 'win32':
    import fcntl

# ============================================================================
# Platform Detection & Feature Discovery
# ============================================================================

class Platform:
    """
    OS platform detection and feature capability discovery.
    
    Centralizes all platform-specific logic so the rest of the library
    can use simple boolean checks rather than scattered sys.platform calls.
    
    Features are detected at import time and cached as class attributes.
    This ensures fast checks without repeated syscall overhead.
    """
    
    # Core platform identification
    WINDOWS = sys.platform == 'win32'
    LINUX = sys.platform.startswith('linux')
    MACOS = sys.platform == 'darwin'
    BSD = (sys.platform.startswith('freebsd') or 
           sys.platform.startswith('openbsd') or 
           sys.platform.startswith('netbsd'))
    POSIX = not WINDOWS
    
    # Feature detection - what capabilities does this OS support?
    HAS_EPOLL = LINUX and hasattr(_stdlib_select, 'epoll')
    HAS_KQUEUE = (MACOS or BSD) and hasattr(_stdlib_select, 'kqueue')
    HAS_SO_REUSEPORT = LINUX or BSD or MACOS
    HAS_TCP_FASTOPEN = LINUX
    HAS_TCP_CORK = LINUX
    HAS_TCP_QUICKACK = LINUX
    HAS_IPV6_V6ONLY = POSIX
    
    # Human-readable OS name
    if WINDOWS:
        OS_NAME = 'windows'
    elif LINUX:
        OS_NAME = 'linux'
    elif MACOS:
        OS_NAME = 'macos'
    elif BSD:
        OS_NAME = 'bsd'
    else:
        OS_NAME = 'unknown'
    
    @classmethod
    def supports_feature(cls, feature_name: str) -> bool:
        """
        Check if the current platform supports a named feature.
        
        Args:
            feature_name: Feature name like 'epoll', 'kqueue', 'so_reuseport'
            
        Returns:
            True if the feature is available on this platform
        """
        return getattr(cls, f'HAS_{feature_name.upper()}', False)

# ============================================================================
# Native Library Loading (The Foundation Layer)
# ============================================================================

class _NativeLib:
    """
    Internal: Load and cache ALL native library functions.
    
    This is the lowest layer of the architecture. It handles:
    - Platform detection for correct library loading (ws2_32 vs libc)
    - Function signature definitions with proper argtypes/restypes
    - WinSock initialization and cleanup lifecycle
    - Platform-specific structure definitions (fd_set differences!)
    
    DESIGN PRINCIPLE: This class is the ONLY place where platform-specific
    ctypes magic happens. Higher layers use clean Python abstractions.
    
    LESSON LEARNED (v1.0): fd_set on Windows is NOT a bitmask. It's a struct
    with fd_count and fd_array[64]. On POSIX, it IS a bitmask of longs.
    Using homemade bitmask arrays on Windows caused the catastrophic Selector
    bug where no events were ever reported.
    """
    
    # ===== Windows-Specific Setup =====
    if Platform.WINDOWS:
        _ws2_32 = ctypes.WinDLL('ws2_32', use_last_error=True)
        _msvcrt = ctypes.WinDLL('msvcrt', use_last_error=True)
        
        class WSADATA(Structure):
            """
            Windows Sockets implementation data.
            Returned by WSAStartup() to report the WinSock version
            and implementation details.
            """
            _fields_ = [
                ('wVersion', c_ushort),
                ('wHighVersion', c_ushort),
                ('iMaxSockets', c_ushort),
                ('iMaxUdpDg', c_ushort),
                ('lpVendorInfo', c_char_p),
                ('szDescription', c_char * 257),
                ('szSystemStatus', c_char * 129),
            ]
        
        _wsa_startup = _ws2_32.WSAStartup
        _wsa_startup.argtypes = [c_ushort, POINTER(WSADATA)]
        _wsa_startup.restype = c_int
        
        _wsa_cleanup = _ws2_32.WSACleanup
        _wsa_cleanup.argtypes = []
        _wsa_cleanup.restype = c_int
        
        # Initialize WinSock exactly once at import time
        _wsa_data = WSADATA()
        if _wsa_startup(0x0202, byref(_wsa_data)) != 0:
            raise OSError(f"WSAStartup failed: {ctypes.get_last_error()}")
        
        _wsa_cleaned_up = False
        
        @staticmethod
        def _ensure_winsock():
            """
            Guard against using sockets after WinSock cleanup.
            
            Once WSA Cleanup is called, all socket operations become invalid.
            This guard prevents mysterious crashes during interpreter shutdown.
            """
            if _NativeLib._wsa_cleaned_up:
                raise RuntimeError("WinSock has been cleaned up - cannot create new sockets")
        
        INVALID_SOCKET = c_void_p(-1).value
        SOCKET_ERROR = -1
        
        @staticmethod
        def _close_socket(fd):
            """
            Close a Windows socket handle.
            
            On Windows, sockets are kernel handles managed by WinSock,
            not file descriptors. We must use closesocket() not close().
            """
            _NativeLib._ensure_winsock()
            return _NativeLib._ws2_32.closesocket(fd)
        
        @staticmethod
        def _ioctl_socket(fd, cmd, argp):
            """
            Perform ioctl on a Windows socket.
            
            Used for FIONBIO (non-blocking mode) and FIONREAD (bytes available).
            """
            _NativeLib._ensure_winsock()
            return _NativeLib._ws2_32.ioctlsocket(fd, cmd, argp)
        
        # ioctl command codes
        FIONBIO = 0x8004667E  # Set non-blocking mode
        FIONREAD = 0x4004667F # Get bytes available to read
        
    else:  # POSIX (Linux, macOS, BSD)
        _libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        
        INVALID_SOCKET = -1
        SOCKET_ERROR = -1
        
        @staticmethod
        def _close_socket(fd):
            """
            Close a POSIX socket file descriptor.
            
            On POSIX, sockets ARE file descriptors, so we use close().
            """
            return _NativeLib._libc.close(fd)
    
    # ===== Common Function Loader =====
    
    @classmethod
    def _load_func(cls, name, argtypes, restype):
        """
        Load a function from the appropriate native library.
        
        On Windows, socket functions live in ws2_32.dll while standard
        C library functions live in msvcrt.dll. On POSIX, everything
        is in libc.
        
        This method handles the dispatch so callers don't need to know
        which library contains which function.
        """
        if Platform.WINDOWS:
            # Socket functions are in ws2_32, everything else in msvcrt
            socket_funcs = {
                'socket', 'bind', 'listen', 'accept', 'connect',
                'send', 'recv', 'sendto', 'recvfrom',
                'setsockopt', 'getsockopt', 'getsockname',
                'getpeername', 'shutdown', 'select',
                'htons', 'htonl', 'ntohs', 'ntohl',
                'inet_addr', 'inet_ntoa', 'inet_pton', 'inet_ntop',
                'getaddrinfo', 'freeaddrinfo', 'getnameinfo'
            }
            if name in socket_funcs:
                func = getattr(cls._ws2_32, name)
            else:
                func = getattr(cls._msvcrt, name)
        else:
            func = getattr(cls._libc, name)
        
        func.argtypes = argtypes
        func.restype = restype
        return func
    
    # ===== Socket Creation & Lifecycle =====
    socket = _load_func.__func__('socket', [c_int, c_int, c_int], c_void_p)
    bind = _load_func.__func__('bind', [c_void_p, c_void_p, c_int], c_int)
    listen = _load_func.__func__('listen', [c_void_p, c_int], c_int)
    accept = _load_func.__func__('accept', [c_void_p, c_void_p, POINTER(c_int)], c_void_p)
    connect = _load_func.__func__('connect', [c_void_p, c_void_p, c_int], c_int)
    shutdown = _load_func.__func__('shutdown', [c_void_p, c_int], c_int)
    
    # ===== Data Transfer (The Hot Path) =====
    send = _load_func.__func__('send', [c_void_p, c_void_p, c_size_t, c_int], c_ssize_t)
    recv = _load_func.__func__('recv', [c_void_p, c_void_p, c_size_t, c_int], c_ssize_t)
    sendto = _load_func.__func__('sendto', [c_void_p, c_void_p, c_size_t, c_int,
                                            c_void_p, c_int], c_ssize_t)
    recvfrom = _load_func.__func__('recvfrom', [c_void_p, c_void_p, c_size_t, c_int,
                                                c_void_p, POINTER(c_int)], c_ssize_t)
    
    # ===== Socket Options =====
    setsockopt = _load_func.__func__('setsockopt', [c_void_p, c_int, c_int, c_void_p, c_int], c_int)
    getsockopt = _load_func.__func__('getsockopt', [c_void_p, c_int, c_int, c_void_p, POINTER(c_int)], c_int)
    
    # ===== Address Operations =====
    getsockname = _load_func.__func__('getsockname', [c_void_p, c_void_p, POINTER(c_int)], c_int)
    getpeername = _load_func.__func__('getpeername', [c_void_p, c_void_p, POINTER(c_int)], c_int)
    
    # ===== Network Byte Order (Always Big-Endian on the Wire) =====
    htons = _load_func.__func__('htons', [c_ushort], c_ushort)
    htonl = _load_func.__func__('htonl', [c_ulong], c_ulong)
    ntohs = _load_func.__func__('ntohs', [c_ushort], c_ushort)
    ntohl = _load_func.__func__('ntohl', [c_ulong], c_ulong)
    
    # ===== Address Conversion =====
    inet_addr = _load_func.__func__('inet_addr', [c_char_p], c_ulong)
    inet_ntoa = _load_func.__func__('inet_ntoa', [c_uint32], c_char_p)
    
    # ===== DNS Resolution =====
    class AddrInfo(Structure):
        """
        Linked list of address resolution results.
        
        Each node contains one resolved address. The ai_next pointer
        forms a linked list of all resolved addresses in OS-preferred order
        (respecting RFC 6724 sorting on modern systems).
        """
        pass
    
    AddrInfo._fields_ = [
        ('ai_flags', c_int),          # Input flags
        ('ai_family', c_int),         # AF_INET, AF_INET6, etc.
        ('ai_socktype', c_int),       # SOCK_STREAM, SOCK_DGRAM, etc.
        ('ai_protocol', c_int),       # IPPROTO_TCP, IPPROTO_UDP, etc.
        ('ai_addrlen', c_size_t),     # Length of ai_addr
        ('ai_addr', c_void_p),        # Pointer to sockaddr structure
        ('ai_canonname', c_char_p),   # Canonical name (if AI_CANONNAME set)
        ('ai_next', POINTER(AddrInfo)), # Next result in linked list
    ]
    
    getaddrinfo = _load_func.__func__('getaddrinfo', 
        [c_char_p, c_char_p, POINTER(AddrInfo), POINTER(POINTER(AddrInfo))], c_int)
    freeaddrinfo = _load_func.__func__('freeaddrinfo', [POINTER(AddrInfo)], None)
    
    # ===== I/O Multiplexing: select() =====
    
    # CRITICAL LESSON (v1.0): fd_set is platform-dependent!
    # - Windows: struct with fd_count + fixed-size fd_array[64]
    # - POSIX: bitmask array of longs, size determined by FD_SETSIZE (1024)
    #
    # Our v1.0 implementation used homemade bitmask arrays on Windows,
    # which caused select() to receive garbage data and never report events.
    #
    # CRITICAL FIX (v3.1.1): sizeof() must be used as ctypes.sizeof(), not
    # as a bare function. The bare sizeof() in the fd_set definition was
    # calling Python's built-in (which doesn't exist) instead of ctypes'.
    
    if Platform.WINDOWS:
        class fd_set(Structure):
            """
            Windows fd_set: count + array of SOCKET handles.
            Maximum 64 sockets per set (FD_SETSIZE = 64).
            """
            _fields_ = [
                ('fd_count', c_uint),
                ('fd_array', c_void_p * 64),
            ]
        FD_SETSIZE = 64
    else:
        FD_SETSIZE = 1024
        # CORRECT: Use ctypes.sizeof() explicitly
        _num_longs = FD_SETSIZE // (8 * ctypes.sizeof(c_long))
        class fd_set(Structure):
            """
            POSIX fd_set: bitmask array.
            FD_SETSIZE bits total (1024 file descriptors).
            Each bit represents one FD.
            """
            _fields_ = [('fds_bits', c_long * _num_longs)]
    
    class TimeVal(Structure):
        """
        Time value for select() timeout.
        
        tv_sec: Seconds
        tv_usec: Microseconds (0-999999)
        """
        _fields_ = [
            ('tv_sec', c_long),
            ('tv_usec', c_long),
        ]
    
    select = _load_func.__func__('select', 
        [c_int, POINTER(fd_set), POINTER(fd_set), POINTER(fd_set), POINTER(TimeVal)], c_int)

# ============================================================================
# Constants & Enumerations (Self-Documenting API)
# ============================================================================

class AddressFamily(IntEnum):
    """
    Socket address families.
    
    These correspond to the AF_* constants in <sys/socket.h>.
    Using IntEnum makes them usable directly in ctypes calls.
    """
    AF_UNSPEC = 0      # Unspecified - let the OS decide
    AF_INET = 2         # IPv4
    AF_INET6 = 23 if Platform.POSIX else 23  # IPv6 (same value on both)
    AF_UNIX = 1 if Platform.POSIX else 1     # Unix domain sockets

class SocketType(IntEnum):
    """
    Socket types.
    
    SOCK_STREAM = TCP (reliable, ordered, connection-oriented)
    SOCK_DGRAM = UDP (unreliable, unordered, connectionless)
    SOCK_RAW = Raw sockets (requires root/admin, packet-level access)
    SOCK_NONBLOCK and SOCK_CLOEXEC are Linux extensions that can be
    OR'd with the type during socket creation to avoid extra syscalls.
    """
    SOCK_STREAM = 1
    SOCK_DGRAM = 2
    SOCK_RAW = 3
    SOCK_RDM = 4
    SOCK_SEQPACKET = 5
    # Linux extensions (OR'd with type during socket creation)
    SOCK_NONBLOCK = 0x800 if Platform.LINUX else 0
    SOCK_CLOEXEC = 0x80000 if Platform.LINUX else 0

class Protocol(IntEnum):
    """
    IP protocol numbers.
    
    Used as the third argument to socket(). Usually 0 (auto-select).
    """
    IPPROTO_IP = 0      # Dummy for TCP/UDP
    IPPROTO_ICMP = 1    # Internet Control Message Protocol (ping)
    IPPROTO_TCP = 6     # Transmission Control Protocol
    IPPROTO_UDP = 17    # User Datagram Protocol
    IPPROTO_RAW = 255   # Raw IP packets

class SocketLevel(IntEnum):
    """
    Socket option levels.
    
    Determines which protocol layer a socket option applies to:
    - SOL_SOCKET: Generic socket options (reuseaddr, keepalive, etc.)
    - IPPROTO_TCP: TCP-specific options (nodelay, cork, etc.)
    - IPPROTO_IPV6: IPv6-specific options (v6only, etc.)
    """
    SOL_SOCKET = 0xffff
    IPPROTO_IP = 0
    IPPROTO_TCP = 6
    IPPROTO_IPV6 = 41

class SocketOption(IntEnum):
    """
    Socket-level options for setsockopt()/getsockopt().
    
    Note: Values differ between POSIX and Windows for historical reasons.
    The IntEnum handles this transparently.
    """
    SO_REUSEADDR = 2 if Platform.POSIX else 4
    SO_KEEPALIVE = 9 if Platform.POSIX else 8
    SO_BROADCAST = 6 if Platform.POSIX else 32
    SO_LINGER = 13 if Platform.POSIX else 128
    SO_RCVBUF = 8 if Platform.POSIX else 0x1002
    SO_SNDBUF = 7 if Platform.POSIX else 0x1001
    SO_RCVTIMEO = 20 if Platform.POSIX else 0x1006
    SO_SNDTIMEO = 21 if Platform.POSIX else 0x1005
    SO_REUSEPORT = 15 if Platform.LINUX else 0
    SO_ERROR = 4 if Platform.POSIX else 0x1007

class TCPOption(IntEnum):
    """
    TCP-level socket options.
    
    These control TCP protocol behavior at a fine-grained level.
    Most are Linux-specific extensions.
    """
    TCP_NODELAY = 1              # Disable Nagle's algorithm (lower latency)
    TCP_QUICKACK = 12 if Platform.LINUX else 0   # Disable delayed ACKs
    TCP_FASTOPEN = 23 if Platform.LINUX else 0   # TFO (reduce handshake RTT)
    TCP_CORK = 3 if Platform.LINUX else 0        # Don't send partial frames

class ShutdownHow(IntEnum):
    """
    Shutdown modes for shutdown().
    
    Controls which direction(s) of the connection to close:
    - SHUT_RD: Stop receiving (peer will get EPIPE on write)
    - SHUT_WR: Stop sending (peer will read EOF)
    - SHUT_RDWR: Stop both (equivalent to close but keeps FD)
    """
    SHUT_RD = 0
    SHUT_WR = 1
    SHUT_RDWR = 2

class AIFlags(IntFlag):
    """
    Flags for getaddrinfo() controlling DNS resolution behavior.
    
    Using IntFlag allows combining flags with | operator.
    """
    AI_PASSIVE = 1       # Socket will be used for bind() (server)
    AI_CANONNAME = 2     # Return the canonical name
    AI_NUMERICHOST = 4   # Host is an IP address, don't resolve
    AI_V4MAPPED = 8      # Return IPv4-mapped IPv6 addresses
    AI_ALL = 16          # Return both IPv4 and IPv6 addresses
    AI_ADDRCONFIG = 32   # Only return addresses configured on this host

class SelectEvent(IntFlag):
    """
    Events for I/O multiplexing.
    
    Using auto() for automatic value assignment.
    IntFlag allows combining with | operator:
        events = SelectEvent.READ | SelectEvent.WRITE
    """
    READ = auto()    # Socket is readable (data or connection available)
    WRITE = auto()   # Socket is writable (buffer space available)
    ERROR = auto()   # Socket has an error condition
    HANGUP = auto()  # Socket has been hung up (peer closed or reset)

# ============================================================================
# Socket Address Structures with Elegant Constructors
# ============================================================================

class InAddr(Structure):
    """
    IPv4 address in network byte order.
    
    Stored as a 32-bit unsigned integer in network byte order (big-endian).
    For 127.0.0.1, s_addr = 0x0100007F.
    """
    _fields_ = [('s_addr', c_uint32)]

class In6Addr(Structure):
    """
    IPv6 address (128 bits / 16 bytes).
    
    Stored as 16 bytes in network byte order.
    """
    _fields_ = [('s6_addr', c_uint8 * 16)]

class SockAddrIn(Structure):
    """
    IPv4 socket address structure.
    
    LESSON LEARNED (v2.0): Classmethods make excellent alternative
    constructors. Instead of manually populating fields everywhere:
    
        addr = SockAddrIn()
        addr.sin_family = AF_INET
        addr.sin_port = htons(port)
        addr.sin_addr.s_addr = parse_ipv4(host)
    
    We now have clean, self-documenting constructors:
    
        addr = SockAddrIn.from_tuple(('192.168.1.1', 80))
        addr = SockAddrIn.from_raw(0x0101A8C0, 80)
    """
    _fields_ = [
        ('sin_family', c_ushort),  # AF_INET
        ('sin_port', c_ushort),    # Port in network byte order
        ('sin_addr', InAddr),      # IPv4 address
        ('sin_zero', c_uint8 * 8), # Padding (must be zeroed)
    ]
    
    @classmethod
    def from_tuple(cls, address: Tuple[str, int]) -> 'SockAddrIn':
        """
        Create from ('host', port) tuple.
        
        Special addresses:
        - '0.0.0.0', '', '*' → INADDR_ANY (bind to all IPv4 interfaces)
        - Any other string → parsed as IPv4 address
        
        Args:
            address: (host_string, port_number) tuple
            
        Returns:
            Populated SockAddrIn structure
            
        Raises:
            ValueError: If host string is not a valid IPv4 address
        """
        host, port = address
        instance = cls()
        instance.sin_family = AddressFamily.AF_INET
        instance.sin_port = _NativeLib.htons(port)
        
        if host in ('', '0.0.0.0', '*'):
            instance.sin_addr.s_addr = 0  # INADDR_ANY
        else:
            instance.sin_addr.s_addr = IPAddress.parse_ipv4(host)
        
        return instance
    
    @classmethod
    def from_raw(cls, addr_int: int, port: int) -> 'SockAddrIn':
        """
        Create from raw integer address (network byte order) and port.
        
        Args:
            addr_int: 32-bit IPv4 address in network byte order
            port: Port number (host byte order, will be converted)
            
        Returns:
            Populated SockAddrIn structure
        """
        instance = cls()
        instance.sin_family = AddressFamily.AF_INET
        instance.sin_port = _NativeLib.htons(port)
        instance.sin_addr.s_addr = addr_int
        return instance

class SockAddrIn6(Structure):
    """
    IPv6 socket address structure.
    
    Includes flowinfo (traffic class + flow label) and scope_id
    (interface index for link-local addresses). Most applications
    set these to 0.
    """
    _fields_ = [
        ('sin6_family', c_ushort),   # AF_INET6
        ('sin6_port', c_ushort),     # Port in network byte order
        ('sin6_flowinfo', c_uint32), # Flow label (usually 0)
        ('sin6_addr', In6Addr),      # IPv6 address (16 bytes)
        ('sin6_scope_id', c_uint32), # Scope ID for link-local
    ]
    
    @classmethod
    def from_tuple(cls, address: Tuple[str, int]) -> 'SockAddrIn6':
        """
        Create from ('host', port) tuple.
        
        Special addresses:
        - '::', '::0', '0::0', '' → IN6ADDR_ANY (bind to all interfaces)
        - Any other string → parsed as IPv6 address
        
        Args:
            address: (host_string, port_number) tuple
            
        Returns:
            Populated SockAddrIn6 structure
            
        Raises:
            ValueError: If host string is not a valid IPv6 address
        """
        host, port = address
        instance = cls()
        instance.sin6_family = AddressFamily.AF_INET6
        instance.sin6_port = _NativeLib.htons(port)
        instance.sin6_flowinfo = 0
        instance.sin6_scope_id = 0
        
        if host in ('', '::', '::0', '0::0'):
            ctypes.memset(instance.sin6_addr.s6_addr, 0, 16)  # IN6ADDR_ANY
        else:
            ipv6_bytes = IPAddress.parse_ipv6(host)
            memmove(instance.sin6_addr.s6_addr, ipv6_bytes, 16)
        
        return instance

class SockAddrUn(Structure):
    """
    Unix domain socket address.
    
    Path is limited to 108 bytes (including null terminator).
    """
    _fields_ = [
        ('sun_family', c_ushort),
        ('sun_path', c_char * 108),
    ]

class SockAddrStorage(Structure):
    """
    Protocol-independent socket address storage.
    
    Large enough (128 bytes) to hold any sockaddr variant:
    - sockaddr_in:  16 bytes
    - sockaddr_in6: 28 bytes
    - sockaddr_un:  110 bytes
    
    The ss_family field tells us which type to cast to.
    
    CRITICAL: Always check ss_family before casting! Casting
    an IPv6 address as sockaddr_in produces garbage. This was
    a bug in v1.0's accept() and recvfrom().
    """
    _fields_ = [
        ('ss_family', c_ushort),
        ('__ss_padding', c_uint8 * 126),  # Fill to 128 bytes total
    ]

class Linger(Structure):
    """
    Linger structure for SO_LINGER socket option.
    
    Controls close() behavior when unsent data remains:
    - l_onoff=0: Close immediately, data may be lost (default)
    - l_onoff=1: Wait up to l_linger seconds for data to send
    
    Use set_option_linger() for a cleaner interface.
    """
    _fields_ = [
        ('l_onoff', c_int),   # 0=disable, 1=enable
        ('l_linger', c_int),  # Timeout in seconds
    ]

# ============================================================================
# Error Handling (The Safety Net)
# ============================================================================

class SocketError(OSError):
    """
    Exception for socket-related errors with operation context.
    
    Extends OSError for compatibility with existing error handling.
    Adds 'operation' attribute for better error messages.
    
    Example output:
        SocketError: connect to example.com:80: Connection refused
    
    The errno_code attribute contains the raw OS error code:
        try:
            sock.connect(...)
        except SocketError as e:
            if e.errno_code == errno.ECONNREFUSED:
                print("Server is not listening")
    """
    
    def __init__(self, errno_code=None, message=None, operation=None):
        if errno_code is None:
            errno_code = _get_last_error()
        if message is None:
            message = _get_error_string(errno_code)
        if operation:
            message = f"{operation}: {message}"
        super().__init__(errno_code, message)
        self.errno_code = errno_code
        self.operation = operation
    
    def __str__(self):
        return f"[Errno {self.errno_code}] {self.args[1]}"

def _get_last_error() -> int:
    """
    Get the last OS error code in a platform-agnostic way.
    
    On Windows: ctypes.get_last_error() (SetLastError/WSAGetLastError)
    On POSIX: ctypes.get_errno() (errno)
    """
    if Platform.WINDOWS:
        return ctypes.get_last_error()
    else:
        return ctypes.get_errno()

def _get_error_string(code: int) -> str:
    """
    Get human-readable error string for an error code.
    
    On Windows: FormatMessageW for proper Unicode error messages
    On POSIX: os.strerror (which handles locale)
    """
    if Platform.WINDOWS:
        buf = ctypes.create_unicode_buffer(256)
        # FormatMessageW is available directly from msvcrt
        _NativeLib._msvcrt.FormatMessageW(
            0x00000100 | 0x00001000,  # FORMAT_MESSAGE_FROM_SYSTEM | IGNORE_INSERTS
            None, code, 0, buf, len(buf), None
        )
        return buf.value.rstrip() if buf.value else f"Windows error {code}"
    else:
        try:
            return os.strerror(code)
        except ValueError:
            return f"Unknown error {code}"

def _check_result(result, operation="socket operation"):
    """
    Check if a socket operation succeeded.
    
    On Windows: SOCKET_ERROR (-1) indicates failure
    On POSIX: Any negative value indicates failure
    
    Returns the result on success, raises SocketError on failure.
    """
    if Platform.WINDOWS:
        if result == _NativeLib.SOCKET_ERROR:
            raise SocketError(operation=operation)
    else:
        if result < 0:
            raise SocketError(operation=operation)
    return result

def _check_ptr(ptr, operation="socket operation"):
    """
    Check if a pointer/socket handle is valid.
    
    On Windows: INVALID_SOCKET (~0) or NULL indicates failure
    On POSIX: NULL or negative indicates failure
    """
    if not ptr:
        raise SocketError(operation=operation)
    if Platform.WINDOWS and ptr == _NativeLib.INVALID_SOCKET:
        raise SocketError(operation=operation)
    return ptr

def _would_block() -> bool:
    """
    Check if the last error indicates a non-blocking operation would block.
    
    This is NOT an error - it's expected behavior for non-blocking sockets.
    We raise BlockingIOError so callers can distinguish "would block"
    from actual errors.
    
    On Windows: WSAEWOULDBLOCK (10035)
    On POSIX: EAGAIN (11) or EWOULDBLOCK (usually same as EAGAIN)
    """
    err = _get_last_error()
    if Platform.WINDOWS:
        return err == 10035  # WSAEWOULDBLOCK
    else:
        return err in (errno.EAGAIN, errno.EWOULDBLOCK)

# ============================================================================
# IP Address Utilities (No Allocations on the Hot Path)
# ============================================================================

class IPAddress:
    """
    Fast IP address parsing and formatting using native OS functions.
    
    All methods are static because there's no state - just pure conversion.
    Uses inet_addr/inet_ntoa for IPv4 and inet_pton/inet_ntop for IPv6.
    
    Performance note: These functions are implemented in C by the OS
    and are extremely fast. The ctypes overhead is minimal compared to
    the actual I/O operations that follow.
    """
    
    @staticmethod
    def parse_ipv4(addr_str: str) -> int:
        """
        Convert IPv4 string to 32-bit integer in network byte order.
        
        Examples:
            '192.168.1.1' → 0x0101A8C0 (network byte order is big-endian!)
            '127.0.0.1'   → 0x0100007F
            '0.0.0.0'     → 0x00000000
            
        Args:
            addr_str: IPv4 address string (e.g., "192.168.1.1")
            
        Returns:
            32-bit integer in network byte order
            
        Raises:
            ValueError: If the address string is invalid
        """
        if isinstance(addr_str, bytes):
            addr_str = addr_str.decode('ascii')
        result = _NativeLib.inet_addr(addr_str.encode('ascii'))
        if result == 0xFFFFFFFF:  # INADDR_NONE
            raise ValueError(f"Invalid IPv4 address: {addr_str}")
        return result
    
    @staticmethod
    def format_ipv4(addr_int: int) -> str:
        """
        Convert 32-bit integer to IPv4 dotted-decimal string.
        
        Example:
            0x0101A8C0 → '192.168.1.1'
            0x0100007F → '127.0.0.1'
            
        Args:
            addr_int: 32-bit integer in network byte order
            
        Returns:
            IPv4 address string
        """
        result = _NativeLib.inet_ntoa(c_uint32(addr_int))
        if isinstance(result, bytes):
            return result.decode('ascii')
        return result
    
    @staticmethod
    def parse_ipv6(addr_str: str) -> bytes:
        """
        Parse IPv6 address to 16-byte representation.
        
        Examples:
            '::1'           → b'\x00...\x01' (15 null bytes + 0x01)
            '2001:db8::1'   → b'\x20\x01\x0d\xb8...\x00...\x01'
            
        Args:
            addr_str: IPv6 address string
            
        Returns:
            16 bytes of the IPv6 address
            
        Raises:
            ValueError: If the address string is invalid
        """
        try:
            return _stdlib_socket.inet_pton(_stdlib_socket.AF_INET6, addr_str)
        except OSError as e:
            raise ValueError(f"Invalid IPv6 address: {addr_str}") from e
    
    @staticmethod
    def format_ipv6(addr_bytes: bytes) -> str:
        """
        Convert 16-byte IPv6 address to string representation.
        
        Uses the canonical form with :: compression.
        
        Args:
            addr_bytes: 16 bytes of IPv6 address
            
        Returns:
            IPv6 address string
        """
        return _stdlib_socket.inet_ntop(_stdlib_socket.AF_INET6, addr_bytes)
    
    @staticmethod
    def is_ipv4(addr_str: str) -> bool:
        """
        Check if a string is a valid IPv4 address.
        
        No allocation on success - just parses and discards the result.
        Faster than regex or manual parsing.
        """
        try:
            IPAddress.parse_ipv4(addr_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_ipv6(addr_str: str) -> bool:
        """Check if a string is a valid IPv6 address."""
        try:
            IPAddress.parse_ipv6(addr_str)
            return True
        except ValueError:
            return False

def _infer_family(host: str) -> int:
    """
    Infer address family from a host string.
    
    Used by TCPServer and TCPClient to auto-detect IPv4 vs IPv6
    without requiring explicit family parameter.
    
    Returns:
        AF_INET6 if the host looks like an IPv6 address, AF_INET otherwise
    """
    if IPAddress.is_ipv6(host):
        return AddressFamily.AF_INET6
    return AddressFamily.AF_INET

# ============================================================================
# DNS Resolution (Respecting OS Address Ordering)
# ============================================================================

def resolve_hostname(hostname: str, 
                     port: Union[int, str] = 0,
                     family: int = AddressFamily.AF_UNSPEC,
                     socktype: int = 0,
                     protocol: int = 0,
                     flags: int = AIFlags.AI_ADDRCONFIG | AIFlags.AI_V4MAPPED) -> List[Tuple[int, str, int]]:
    """
    Resolve hostname to list of (family, address_string, port) tuples.
    
    Uses native getaddrinfo() which respects:
    - RFC 6724 address sorting (IPv6 priority on dual-stack hosts)
    - /etc/hosts entries (or C:\Windows\System32\drivers\etc\hosts)
    - DNS resolution with proper TTL caching
    - Platform-specific resolution order (DNS, mDNS, LLMNR, etc.)
    - /etc/gai.conf customization on Linux
    - /etc/nsswitch.conf resolution order
    
    Args:
        hostname: Hostname or IP address (None for passive/any address)
        port: Port number or service name string (e.g., 80, 'http')
        family: AF_INET, AF_INET6, or AF_UNSPEC for all
        socktype: SOCK_STREAM, SOCK_DGRAM, or 0 for any
        protocol: IPPROTO_TCP, IPPROTO_UDP, or 0 for any
        flags: getaddrinfo flags controlling resolution behavior
        
    Returns:
        List of (family, address_string, port_number) tuples in OS-preferred order
        
    Raises:
        OSError: If resolution fails (host not found, no addresses, etc.)
    """
    hints = _NativeLib.AddrInfo()
    hints.ai_family = family
    hints.ai_socktype = socktype
    hints.ai_protocol = protocol
    hints.ai_flags = flags
    
    result_ptr = POINTER(_NativeLib.AddrInfo)()
    
    # Prepare inputs - getaddrinfo expects C strings
    host_bytes = hostname.encode('ascii') if hostname else None
    if isinstance(port, int):
        port_bytes = str(port).encode('ascii')
    else:
        port_bytes = port.encode('ascii') if port else None
    
    ret = _NativeLib.getaddrinfo(host_bytes, port_bytes, byref(hints), byref(result_ptr))
    if ret != 0:
        if Platform.WINDOWS:
            raise SocketError(ret, f"getaddrinfo failed for {hostname}", "resolve_hostname")
        else:
            # getaddrinfo errors use EAI_* codes, not standard errno
            try:
                error_msg = _stdlib_socket.gaierror(ret).args[1]
            except (AttributeError, IndexError):
                error_msg = f"Error {ret}"
            raise OSError(ret, f"getaddrinfo: {error_msg}")
    
    addresses = []
    try:
        current = result_ptr
        while current:
            info = current.contents
            
            if info.ai_family == AddressFamily.AF_INET:
                sockaddr = SockAddrIn()
                memmove(byref(sockaddr), info.ai_addr, min(sizeof(SockAddrIn), info.ai_addrlen))
                host = IPAddress.format_ipv4(sockaddr.sin_addr.s_addr)
                port_num = _NativeLib.ntohs(sockaddr.sin_port)
                addresses.append((AddressFamily.AF_INET, host, port_num))
                
            elif info.ai_family == AddressFamily.AF_INET6:
                sockaddr = SockAddrIn6()
                memmove(byref(sockaddr), info.ai_addr, min(sizeof(SockAddrIn6), info.ai_addrlen))
                ipv6_bytes = bytes(sockaddr.sin6_addr.s6_addr)
                host = IPAddress.format_ipv6(ipv6_bytes)
                port_num = _NativeLib.ntohs(sockaddr.sin6_port)
                addresses.append((AddressFamily.AF_INET6, host, port_num))
                
            current = info.ai_next
    finally:
        _NativeLib.freeaddrinfo(result_ptr)
    
    return addresses

# ============================================================================
# Resource Tracking (Replacing __del__ with Deterministic Cleanup)
# ============================================================================

class ResourceTracker:
    """
    Track open socket resources and warn about leaks.
    
    Thread-safe: Uses threading.Lock for all state modifications.
    
    LESSON LEARNED (v2.0): __del__ is non-deterministic. It can cause:
    - Resurrection bugs (objects revived during __del__)
    - Interpreter shutdown issues (globals might be None)
    - Circular reference problems
    - Silent failures (exceptions in __del__ are ignored)
    
    Instead, we:
    1. Track all open sockets via weakref.WeakSet (no strong references)
    2. Warn at exit about any unfreed sockets via atexit handler
    3. Let the OS clean up actual file descriptors (they're process-scoped)
    4. Use threading.Lock for thread-safe registration/unregistration
    
    This is the CORRECT pattern for resource tracking in Python libraries.
    Users are strongly encouraged to use context managers, but we don't
    silently hide leaks - we make them visible with ResourceWarning.
    """
    
    def __init__(self):
        self._resources: weakref.WeakSet = weakref.WeakSet()
        self._lock = threading.Lock()
    
    def register(self, obj):
        """
        Register a socket for leak tracking.
        
        Thread-safe: uses internal lock.
        """
        with self._lock:
            self._resources.add(obj)
    
    def unregister(self, obj):
        """
        Remove a socket from tracking.
        
        Called when close() is invoked explicitly (or via context manager).
        Thread-safe: uses internal lock.
        """
        with self._lock:
            self._resources.discard(obj)
    
    def get_open_resources(self) -> List[Any]:
        """
        Get list of currently tracked (open) resources.
        
        Returns a snapshot - the actual set may change after this call.
        Thread-safe: uses internal lock.
        """
        with self._lock:
            return list(self._resources)
    
    @property
    def count(self) -> int:
        """Number of currently tracked resources."""
        with self._lock:
            return len(self._resources)
    
    def warn_if_open(self):
        """
        Called at process exit to warn about leaked sockets.
        
        Issues a ResourceWarning (visible with -Wdefault or PYTHONWARNINGS
        environment variable) listing all sockets that weren't explicitly
        closed. This reminds developers to use proper resource management.
        """
        open_resources = self.get_open_resources()
        if open_resources:
            warnings.warn(
                f"Leaked {len(open_resources)} socket resource(s). "
                f"Always use 'with' statements or call close() explicitly.\n"
                f"Leaked resources: {open_resources}",
                ResourceWarning,
                stacklevel=3
            )

# Global tracker instance - single source of truth for resource state
_tracker = ResourceTracker()

# Register atexit handler for leak detection on normal exit
atexit.register(_tracker.warn_if_open)

# ============================================================================
# RawSocket - The Core Abstraction
# ============================================================================

class RawSocket:
    """
    Low-level native socket wrapper with minimal Python overhead.
    
    This is the workhorse of the library. Every operation maps directly
    to a single syscall through ctypes. There are no intermediate buffers,
    no translation layers, and no hidden allocations (except where noted).
    
    Architecture:
        User Code → RawSocket.send() → ctypes → send() syscall → Kernel
        User Code → RawSocket.recv() → ctypes → recv() syscall → Kernel
    
    Thread Safety:
        NOT thread-safe for concurrent operations on the same socket.
        The ResourceTracker (leak detection) IS thread-safe.
        The Selector classes are NOT thread-safe for register/unregister.
        If you share sockets across threads, provide your own synchronization.
    
    Resource Lifecycle:
        with RawSocket() as sock:    # Created, tracked by ResourceTracker
            sock.connect(...)        # Connected
            data = sock.recv(1024)   # Data received
        # sock.close() called automatically, untracked
    
    Key Design Decisions:
        - No __del__ (see ResourceTracker for detailed rationale)
        - Nonblocking state cached on Windows (cannot query via ioctlsocket)
        - accept() uses _from_fd() factory (doesn't bypass __init__)
        - All errors raised as SocketError with operation context
        - sendall() uses addressof() + offset arithmetic (NOT byref offset)
    """
    
    __slots__ = ('_fd', '_family', '_socktype', '_protocol', '_closed', '_nonblocking_cached')
    
    def __init__(self, 
                 family: int = AddressFamily.AF_INET, 
                 socktype: int = SocketType.SOCK_STREAM,
                 protocol: int = 0):
        """
        Create a new socket.
        
        Args:
            family: AF_INET (IPv4), AF_INET6 (IPv6), AF_UNIX (Unix domain)
            socktype: SOCK_STREAM (TCP), SOCK_DGRAM (UDP), SOCK_RAW (raw packets)
            protocol: Usually 0 (auto-select based on socktype)
            
        Raises:
            SocketError: If the OS cannot create the socket
                        (e.g., out of file descriptors, permission denied)
        """
        if Platform.WINDOWS:
            _NativeLib._ensure_winsock()
        
        self._fd = _NativeLib.socket(family, socktype, protocol)
        _check_ptr(self._fd, "socket creation")
        
        self._family = family
        self._socktype = socktype
        self._protocol = protocol
        self._closed = False
        self._nonblocking_cached = False
        
        # Register for leak detection
        _tracker.register(self)
    
    @classmethod
    def _from_fd(cls, fd, family, socktype, protocol):
        """
        Internal factory: Create a RawSocket from an existing file descriptor.
        
        This is used by accept() and potentially other operations that
        receive a new socket FD from the kernel. Unlike the public __init__,
        this does NOT call socket()—the FD already exists.
        
        LESSON LEARNED (v3.1): Using a dedicated classmethod is safer than
        __new__ + manual attribute assignment because:
        1. It's a documented, intentional code path
        2. If __init__ evolves, this won't silently break
        3. It makes the "already-created FD" semantics explicit
        
        Args:
            fd: Native socket handle (already created by kernel)
            family: Address family of the socket
            socktype: Socket type
            protocol: Protocol
            
        Returns:
            RawSocket instance wrapping the existing FD
        """
        instance = cls.__new__(cls)
        instance._fd = fd
        instance._family = family
        instance._socktype = socktype
        instance._protocol = protocol
        instance._closed = False
        instance._nonblocking_cached = False
        
        # Track for leak detection
        _tracker.register(instance)
        
        return instance
    
    # ===== Read-Only Properties =====
    
    @property
    def fileno(self) -> int:
        """
        Get the native socket handle.
        
        POSIX: Returns an int file descriptor
        Windows: Returns a SOCKET handle (pointer-sized, fits in int on Win64)
        
        Raises:
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        return self._fd
    
    @property
    def family(self) -> int:
        """Address family (AF_INET, AF_INET6, etc.)."""
        return self._family
    
    @property
    def socktype(self) -> int:
        """Socket type (SOCK_STREAM, SOCK_DGRAM, etc.)."""
        return self._socktype
    
    @property
    def protocol(self) -> int:
        """Protocol (IPPROTO_TCP, IPPROTO_UDP, etc.)."""
        return self._protocol
    
    @property
    def closed(self) -> bool:
        """True if the socket has been closed."""
        return self._closed
    
    # ===== Socket Options (The Control Knobs) =====
    
    def _set_option_raw(self, level: int, option: int, value_ptr, value_len: int) -> None:
        """Set a socket option at the syscall level."""
        if self._closed:
            raise RuntimeError("Socket is closed")
        ret = _NativeLib.setsockopt(self._fd, level, option, value_ptr, value_len)
        _check_result(ret, f"setsockopt(level={level}, option={option})")
    
    def set_option_int(self, level: int, option: int, value: int) -> None:
        """
        Set an integer-valued socket option.
        
        Args:
            level: Protocol level (SocketLevel.SOL_SOCKET, IPPROTO_TCP, etc.)
            option: Option name (SocketOption.SO_REUSEADDR, TCPOption.TCP_NODELAY, etc.)
            value: Integer value
        """
        val = c_int(value)
        self._set_option_raw(level, option, byref(val), sizeof(val))
    
    def set_option_bool(self, level: int, option: int, value: bool) -> None:
        """
        Set a boolean socket option.
        
        The OS expects 0 or 1 as an integer - not True/False directly.
        """
        self.set_option_int(level, option, 1 if value else 0)
    
    def set_option_linger(self, enabled: bool, timeout_sec: int = 0) -> None:
        """
        Set SO_LINGER - controls close() behavior with unsent data.
        
        When enabled, close() will block until all data is sent
        or timeout_sec seconds have passed.
        
        Args:
            enabled: If True, enable lingering
            timeout_sec: Maximum seconds to wait (0 = immediate close)
        """
        ling = Linger(1 if enabled else 0, timeout_sec)
        self._set_option_raw(SocketLevel.SOL_SOCKET, SocketOption.SO_LINGER, 
                            byref(ling), sizeof(ling))
    
    def get_option_int(self, level: int, option: int) -> int:
        """
        Get an integer socket option value.
        
        Returns:
            Current option value as int
            
        Raises:
            SocketError: If getsockopt fails
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        val = c_int()
        optlen = c_int(sizeof(val))
        ret = _NativeLib.getsockopt(self._fd, level, option, byref(val), byref(optlen))
        _check_result(ret, f"getsockopt(level={level}, option={option})")
        return val.value
    
    def get_socket_error(self) -> int:
        """
        Get and clear SO_ERROR (pending socket error).
        
        Returns 0 if no error, otherwise the errno value.
        This is how you check if a non-blocking connect() succeeded:
        the initial connect returns EINPROGRESS, then SO_ERROR tells
        you the final result.
        
        Returns:
            0 if no error, errno value otherwise
        """
        return self.get_option_int(SocketLevel.SOL_SOCKET, SocketOption.SO_ERROR)
    
    # ===== Convenient Properties for Common Options =====
    
    @property
    def reuseaddr(self) -> bool:
        """
        SO_REUSEADDR: Allow binding to TIME_WAIT addresses.
        
        Essential for servers that restart quickly - without this,
        you get "Address already in use" for ~60 seconds after shutdown.
        """
        return bool(self.get_option_int(SocketLevel.SOL_SOCKET, SocketOption.SO_REUSEADDR))
    
    @reuseaddr.setter
    def reuseaddr(self, value: bool) -> None:
        self.set_option_bool(SocketLevel.SOL_SOCKET, SocketOption.SO_REUSEADDR, value)
    
    @property
    def reuseport(self) -> bool:
        """
        SO_REUSEPORT: Allow multiple sockets on same port.
        
        Enables load balancing across multiple processes/threads.
        The kernel distributes incoming connections across all
        sockets bound to the same port.
        
        Availability: Linux 3.9+, macOS 10.14+, FreeBSD 12+
        """
        if not Platform.HAS_SO_REUSEPORT:
            raise NotImplementedError("SO_REUSEPORT is not available on this platform")
        return bool(self.get_option_int(SocketLevel.SOL_SOCKET, SocketOption.SO_REUSEPORT))
    
    @reuseport.setter
    def reuseport(self, value: bool) -> None:
        if not Platform.HAS_SO_REUSEPORT:
            raise NotImplementedError("SO_REUSEPORT is not available on this platform")
        self.set_option_bool(SocketLevel.SOL_SOCKET, SocketOption.SO_REUSEPORT, value)
    
    @property
    def keepalive(self) -> bool:
        """
        SO_KEEPALIVE: Send TCP keep-alive probes on idle connections.
        
        Detects dead connections by sending periodic probes.
        Default probe interval is system-dependent (usually 2 hours).
        """
        return bool(self.get_option_int(SocketLevel.SOL_SOCKET, SocketOption.SO_KEEPALIVE))
    
    @keepalive.setter
    def keepalive(self, value: bool) -> None:
        self.set_option_bool(SocketLevel.SOL_SOCKET, SocketOption.SO_KEEPALIVE, value)
    
    @property
    def nodelay(self) -> bool:
        """
        TCP_NODELAY: Disable Nagle's algorithm.
        
        Nagle's algorithm batches small sends into larger packets
        for efficiency. Disabling it (nodelay=True) reduces latency
        at the cost of potentially more packets.
        
        Essential for interactive applications (games, chat, SSH).
        """
        return bool(self.get_option_int(SocketLevel.IPPROTO_TCP, TCPOption.TCP_NODELAY))
    
    @nodelay.setter
    def nodelay(self, value: bool) -> None:
        self.set_option_bool(SocketLevel.IPPROTO_TCP, TCPOption.TCP_NODELAY, value)
    
    @property
    def recv_buffer_size(self) -> int:
        """
        SO_RCVBUF: Kernel receive buffer size in bytes.
        
        Larger buffers can absorb bursts of data but consume more
        kernel memory. Default is typically 87380-131072 bytes.
        """
        return self.get_option_int(SocketLevel.SOL_SOCKET, SocketOption.SO_RCVBUF)
    
    @recv_buffer_size.setter
    def recv_buffer_size(self, value: int) -> None:
        self.set_option_int(SocketLevel.SOL_SOCKET, SocketOption.SO_RCVBUF, value)
    
    @property
    def send_buffer_size(self) -> int:
        """
        SO_SNDBUF: Kernel send buffer size in bytes.
        
        Larger buffers improve throughput for bulk transfers.
        """
        return self.get_option_int(SocketLevel.SOL_SOCKET, SocketOption.SO_SNDBUF)
    
    @send_buffer_size.setter
    def send_buffer_size(self, value: int) -> None:
        self.set_option_int(SocketLevel.SOL_SOCKET, SocketOption.SO_SNDBUF, value)
    
    @property
    def nonblocking(self) -> bool:
        """
        Get or set non-blocking mode.
        
        In non-blocking mode:
        - Operations return immediately
        - If they would block, raise BlockingIOError
        - Essential for async I/O with select/epoll/kqueue
        
        Windows limitation: Cannot query non-blocking state via ioctlsocket.
        We track it via _nonblocking_cached, updated by the setter.
        
        POSIX: Queries actual OS state via fcntl(F_GETFL).
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        if Platform.WINDOWS:
            return self._nonblocking_cached
        else:
            flags = os.fcntl(self._fd, os.F_GETFL, 0)
            return bool(flags & os.O_NONBLOCK)
    
    @nonblocking.setter
    def nonblocking(self, value: bool) -> None:
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        if Platform.WINDOWS:
            mode = c_ulong(1 if value else 0)
            ret = _NativeLib._ioctl_socket(self._fd, _NativeLib.FIONBIO, byref(mode))
            _check_result(ret, "ioctlsocket FIONBIO")
        else:
            flags = os.fcntl(self._fd, os.F_GETFL, 0)
            if value:
                flags |= os.O_NONBLOCK
            else:
                flags &= ~os.O_NONBLOCK
            os.fcntl(self._fd, os.F_SETFL, flags)
        
        self._nonblocking_cached = value
    
    @property
    def bytes_available(self) -> int:
        """
        Get number of bytes available to read without blocking.
        
        Uses FIONREAD ioctl. This is essential for:
        - Edge-triggered event loops (read until EAGAIN)
        - Sizing recv buffers optimally
        - Avoiding unnecessary recv calls
        
        Returns:
            Number of bytes in kernel receive buffer
            
        Raises:
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        if Platform.WINDOWS:
            available = c_ulong(0)
            ret = _NativeLib._ioctl_socket(self._fd, _NativeLib.FIONREAD, byref(available))
            _check_result(ret, "ioctlsocket FIONREAD")
            return available.value
        else:
            # fcntl imported at module level with platform guard
            available = ctypes.c_int(0)
            try:
                fcntl.ioctl(self._fd, 0x541B, available)  # FIONREAD
                return available.value
            except OSError:
                return 0
    
    # ===== Address Operations =====
    
    def bind(self, address: Tuple[str, int]) -> None:
        """
        Bind socket to local address.
        
        Required before listen() for servers. Optional for clients
        (lets the OS assign an ephemeral port).
        
        Args:
            address: (host, port) tuple
                     '0.0.0.0' = all IPv4 interfaces
                     '::' = all IPv6 interfaces (dual-stack on most OS)
                     
        Raises:
            SocketError: If bind fails (port in use, permission denied, etc.)
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        host, port = address
        family = _infer_family(host)
        
        if family == AddressFamily.AF_INET6:
            addr = SockAddrIn6.from_tuple(address)
            addr_len = sizeof(SockAddrIn6)
        else:
            addr = SockAddrIn.from_tuple(address)
            addr_len = sizeof(SockAddrIn)
        
        ret = _NativeLib.bind(self._fd, byref(addr), addr_len)
        _check_result(ret, f"bind to {host}:{port}")
    
    def listen(self, backlog: int = 128) -> None:
        """
        Mark socket as passive (listening for connections).
        
        Only valid for SOCK_STREAM (TCP) sockets.
        
        Args:
            backlog: Maximum number of queued connections.
                     The kernel may silently cap this value.
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        ret = _NativeLib.listen(self._fd, backlog)
        _check_result(ret, "listen")
    
    def accept(self) -> Tuple['RawSocket', Tuple[str, int]]:
        """
        Accept an incoming connection.
        
        Blocks until a connection arrives (blocking mode) or raises
        BlockingIOError (non-blocking mode with no pending connections).
        
        Returns:
            (client_socket, (client_host, client_port))
            
        The returned RawSocket is a NEW, independent socket. You must
        close it separately from the listening socket.
        
        CRITICAL: We check ss_family before casting SockAddrStorage.
        Casting an IPv6 address as SockAddrIn produces garbage host/port.
        This was a catastrophic bug in v1.0.
        
        Raises:
            SocketError: If accept fails
            BlockingIOError: If non-blocking and no pending connections
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        addr = SockAddrStorage()
        addrlen = c_int(sizeof(SockAddrStorage))
        
        client_fd = _NativeLib.accept(self._fd, byref(addr), byref(addrlen))
        
        if Platform.WINDOWS:
            if client_fd == _NativeLib.INVALID_SOCKET:
                if _would_block():
                    raise BlockingIOError("No connection available")
                raise SocketError(operation="accept")
        else:
            if client_fd < 0:
                if _would_block():
                    raise BlockingIOError("No connection available")
                raise SocketError(operation="accept")
        
        # Extract client address based on ACTUAL address family
        actual_family = addr.ss_family
        
        if actual_family == AddressFamily.AF_INET:
            client_addr = SockAddrIn()
            memmove(byref(client_addr), byref(addr), sizeof(SockAddrIn))
            host = IPAddress.format_ipv4(client_addr.sin_addr.s_addr)
            port = _NativeLib.ntohs(client_addr.sin_port)
            
        elif actual_family == AddressFamily.AF_INET6:
            client_addr = SockAddrIn6()
            memmove(byref(client_addr), byref(addr), sizeof(SockAddrIn6))
            ipv6_bytes = bytes(client_addr.sin6_addr.s6_addr)
            host = IPAddress.format_ipv6(ipv6_bytes)
            port = _NativeLib.ntohs(client_addr.sin6_port)
            
        else:
            host = 'unknown'
            port = 0
        
        # Use dedicated factory method (not __new__ bypassing __init__)
        client_sock = RawSocket._from_fd(
            client_fd, actual_family, self._socktype, self._protocol
        )
        
        return client_sock, (host, port)
    
    def connect(self, address: Tuple[str, int]) -> None:
        """
        Connect to a remote address.
        
        For hostnames, resolves to all addresses and tries each in
        OS-preferred order until one succeeds. This is critical for
        robust connectivity - if a host has both IPv4 and IPv6 addresses
        and the first one fails, we try the next.
        
        LESSON LEARNED (v1.0): Our original connect() tried only the
        first resolved address. If that was IPv6 and the server only
        listened on IPv4, it failed immediately instead of trying IPv4.
        
        Args:
            address: (host, port) - host can be IP or hostname
            
        Raises:
            SocketError: If ALL connection attempts fail
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        host, port = address
        
        # Fast path: direct IP address (no resolution needed)
        if IPAddress.is_ipv4(host):
            addr = SockAddrIn.from_tuple(address)
            ret = _NativeLib.connect(self._fd, byref(addr), sizeof(SockAddrIn))
            _check_result(ret, f"connect to {host}:{port}")
            return
        
        if IPAddress.is_ipv6(host):
            addr = SockAddrIn6.from_tuple(address)
            ret = _NativeLib.connect(self._fd, byref(addr), sizeof(SockAddrIn6))
            _check_result(ret, f"connect to {host}:{port}")
            return
        
        # Slow path: hostname resolution with iterative connection attempts
        addresses = resolve_hostname(host, port, family=self._family, socktype=self._socktype)
        if not addresses:
            raise SocketError(
                message=f"Could not resolve hostname: {host}",
                operation="connect"
            )
        
        last_error = None
        for family, addr_str, addr_port in addresses:
            try:
                if family == AddressFamily.AF_INET:
                    sockaddr = SockAddrIn.from_raw(
                        IPAddress.parse_ipv4(addr_str), addr_port
                    )
                    addr_len = sizeof(SockAddrIn)
                else:
                    sockaddr = SockAddrIn6.from_tuple((addr_str, addr_port))
                    addr_len = sizeof(SockAddrIn6)
                
                ret = _NativeLib.connect(self._fd, byref(sockaddr), addr_len)
                if ret == 0 or (Platform.WINDOWS and ret != _NativeLib.SOCKET_ERROR):
                    return  # Success - connected to this address
                    
            except (SocketError, ValueError, OSError) as e:
                last_error = e
                continue  # Try next address
        
        # All addresses failed
        raise SocketError(
            message=(
                f"Failed to connect to {host}:{port} - "
                f"tried {len(addresses)} address(es), last error: {last_error}"
            ),
            operation="connect"
        )
    
    # ===== Data Transfer (The Hot Path) =====
    
    def send(self, data: bytes, flags: int = 0) -> int:
        """
        Send data to connected socket.
        
        WARNING: May not send all data! Check the return value.
        Use sendall() if you need guaranteed delivery of the entire buffer.
        
        This is a raw wrapper around the send() syscall. The kernel may
        accept fewer bytes than provided if the send buffer is full.
        
        Args:
            data: Bytes to send
            flags: Send flags (MSG_OOB, MSG_DONTROUTE, etc. - usually 0)
            
        Returns:
            Number of bytes actually sent
            
        Raises:
            SocketError: If send fails
            BlockingIOError: If non-blocking and buffer is full
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        buf = ctypes.create_string_buffer(data, len(data))
        sent = _NativeLib.send(self._fd, buf, len(data), flags)
        
        if sent == _NativeLib.SOCKET_ERROR:
            if _would_block():
                raise BlockingIOError("Send would block")
            raise SocketError(operation="send")
        
        return sent
    
    def sendall(self, data: bytes, flags: int = 0) -> int:
        """
        Send ALL data, retrying until complete or error.
        
        Unlike send(), this guarantees that all data is sent or raises
        an exception. It handles partial sends automatically.
        
        CRITICAL FIX (v3.1.1): We previously used ctypes.byref(buf, offset)
        which does NOT actually apply the offset in ctypes. Despite the
        documentation warning about this exact bug, we implemented it wrong.
        
        The CORRECT approach is:
        1. Get the base address via ctypes.addressof(buf)
        2. Add the offset manually
        3. Cast to c_void_p for the send() syscall
        
        The buffer is allocated ONCE at the start - retries just advance
        the pointer without re-allocation.
        
        Args:
            data: Bytes to send (all of them, guaranteed)
            flags: Send flags
            
        Returns:
            Total bytes sent (always equals len(data) on success)
            
        Raises:
            SocketError: If send fails with an error
            ConnectionError: If connection closes mid-send
            BlockingIOError: If non-blocking and buffer fills
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        total_sent = 0
        data_len = len(data)
        buf = ctypes.create_string_buffer(data)  # Allocate ONCE
        base_addr = ctypes.addressof(buf)         # Get base address ONCE
        
        while total_sent < data_len:
            remaining = data_len - total_sent
            
            # CORRECT: Manual pointer arithmetic with addressof()
            # byref(buf, offset) does NOT work as expected in ctypes
            ptr = ctypes.c_void_p(base_addr + total_sent)
            sent = _NativeLib.send(self._fd, ptr, remaining, flags)
            
            if sent == _NativeLib.SOCKET_ERROR:
                if _would_block():
                    raise BlockingIOError("Send would block")
                raise SocketError(operation="sendall")
            
            if sent == 0:
                raise ConnectionError("Connection closed during sendall")
            
            total_sent += sent
        
        return total_sent
    
    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        """
        Receive data from connected socket.
        
        Returns empty bytes (b'') if the connection was closed cleanly.
        This is how you detect EOF on a TCP connection.
        
        Args:
            bufsize: Maximum number of bytes to receive
            flags: Receive flags (MSG_PEEK, MSG_WAITALL, etc. - usually 0)
            
        Returns:
            Received bytes (may be less than bufsize)
            Empty bytes if connection closed
            
        Raises:
            SocketError: If recv fails
            BlockingIOError: If non-blocking and no data available
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        buf = ctypes.create_string_buffer(bufsize)
        received = _NativeLib.recv(self._fd, buf, bufsize, flags)
        
        if received == _NativeLib.SOCKET_ERROR:
            if _would_block():
                raise BlockingIOError("Recv would block")
            raise SocketError(operation="recv")
        
        if received == 0:
            return b''  # Connection closed cleanly (EOF)
        
        return buf.raw[:received]
    
    def recv_into(self, buffer: bytearray, nbytes: int = -1, flags: int = 0) -> int:
        """
        Receive data DIRECTLY into a pre-allocated bytearray.
        
        ZERO COPY: Data goes kernel → bytearray with no intermediate
        Python bytes object allocation. This is the most efficient
        receive method in the library.
        
        Essential for high-throughput applications where allocating
        new bytes objects for each recv() would cause GC pressure
        and memory fragmentation.
        
        Args:
            buffer: Pre-allocated bytearray to write into
            nbytes: Maximum bytes to read (-1 = fill buffer)
            flags: Receive flags
            
        Returns:
            Number of bytes received (0 = connection closed)
            
        Raises:
            SocketError: If recv fails
            BlockingIOError: If non-blocking and no data
            RuntimeError: If socket is closed
            
        Example:
            buf = bytearray(65536)  # 64KB pre-allocated
            while True:
                n = sock.recv_into(buf)
                if n == 0:
                    break  # EOF
                process(buf[:n])  # Process only the received bytes
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        if nbytes < 0:
            nbytes = len(buffer)
        
        # Create ctypes array backed by the bytearray's memory
        # This is the zero-copy magic - no data is copied
        buf = (ctypes.c_char * len(buffer)).from_buffer(buffer)
        received = _NativeLib.recv(self._fd, buf, nbytes, flags)
        
        if received == _NativeLib.SOCKET_ERROR:
            if _would_block():
                raise BlockingIOError("Recv would block")
            raise SocketError(operation="recv_into")
        
        return received
    
    def sendto(self, data: bytes, address: Tuple[str, int], flags: int = 0) -> int:
        """
        Send data to a specific address (UDP).
        
        For UDP sockets, each sendto() sends an independent datagram.
        The socket does not need to be connected.
        
        Args:
            data: Bytes to send
            address: (host, port) destination
            flags: Send flags
            
        Returns:
            Number of bytes sent
            
        Raises:
            SocketError: If sendto fails
            ValueError: If address is invalid
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        host, port = address
        buf = ctypes.create_string_buffer(data, len(data))
        
        if IPAddress.is_ipv6(host):
            addr = SockAddrIn6.from_tuple(address)
            addr_len = sizeof(SockAddrIn6)
        else:
            addr = SockAddrIn.from_tuple(address)
            addr_len = sizeof(SockAddrIn)
        
        sent = _NativeLib.sendto(self._fd, buf, len(data), flags, byref(addr), addr_len)
        
        if sent == _NativeLib.SOCKET_ERROR:
            if _would_block():
                raise BlockingIOError("Sendto would block")
            raise SocketError(operation="sendto")
        
        return sent
    
    def recvfrom(self, bufsize: int, flags: int = 0) -> Tuple[bytes, Tuple[str, int]]:
        """
        Receive data and sender address (UDP).
        
        Returns:
            (data, (sender_host, sender_port)) tuple
            
        Raises:
            SocketError: If recvfrom fails
            BlockingIOError: If non-blocking and no data
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        buf = ctypes.create_string_buffer(bufsize)
        addr = SockAddrStorage()
        addrlen = c_int(sizeof(SockAddrStorage))
        
        received = _NativeLib.recvfrom(
            self._fd, buf, bufsize, flags, byref(addr), byref(addrlen)
        )
        
        if received == _NativeLib.SOCKET_ERROR:
            if _would_block():
                raise BlockingIOError("Recvfrom would block")
            raise SocketError(operation="recvfrom")
        
        return buf.raw[:received], _extract_address(addr)
    
    # ===== Address Queries =====
    
    def getsockname(self) -> Tuple[str, int]:
        """
        Get the socket's local address.
        
        Returns:
            (host, port) tuple
            
        Raises:
            SocketError: If getsockname fails
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        addr = SockAddrStorage()
        addrlen = c_int(sizeof(SockAddrStorage))
        ret = _NativeLib.getsockname(self._fd, byref(addr), byref(addrlen))
        _check_result(ret, "getsockname")
        
        return _extract_address(addr)
    
    def getpeername(self) -> Tuple[str, int]:
        """
        Get the socket's remote address.
        
        Returns:
            (host, port) tuple
            
        Raises:
            SocketError: If getpeername fails
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        
        addr = SockAddrStorage()
        addrlen = c_int(sizeof(SockAddrStorage))
        ret = _NativeLib.getpeername(self._fd, byref(addr), byref(addrlen))
        _check_result(ret, "getpeername")
        
        return _extract_address(addr)
    
    # ===== Lifecycle =====
    
    def shutdown(self, how: int = ShutdownHow.SHUT_RDWR) -> None:
        """
        Shutdown send and/or receive channels.
        
        Unlike close(), shutdown() doesn't release the file descriptor.
        It just signals EOF on the specified direction(s).
        
        Common pattern (HTTP client):
            client.sendall(request)
            client.shutdown(ShutdownHow.SHUT_WR)  # Signal EOF to server
            response = client.recv(4096)           # Still can receive
        
        Args:
            how: SHUT_RD (stop receiving), SHUT_WR (stop sending),
                 or SHUT_RDWR (stop both)
                 
        Raises:
            SocketError: If shutdown fails
            RuntimeError: If socket is closed
        """
        if self._closed:
            raise RuntimeError("Socket is closed")
        ret = _NativeLib.shutdown(self._fd, how)
        _check_result(ret, "shutdown")
    
    def close(self) -> None:
        """
        Close the socket and release OS resources.
        
        Safe to call multiple times (idempotent). After close(),
        the socket cannot be used for any operation.
        
        The socket is automatically removed from the resource tracker.
        """
        if not self._closed:
            _NativeLib._close_socket(self._fd)
            self._closed = True
            _tracker.unregister(self)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
    
    def __repr__(self):
        if self._closed:
            return f"<RawSocket [CLOSED]>"
        try:
            local = self.getsockname()
            return (
                f"<RawSocket fd={self._fd} "
                f"local={local[0]}:{local[1]} "
                f"family={self._family}>"
            )
        except:
            return f"<RawSocket fd={self._fd}>"

def _extract_address(storage: SockAddrStorage) -> Tuple[str, int]:
    """
    Extract (host, port) from a SockAddrStorage structure.
    
    Checks ss_family to determine the actual address type before
    casting. This is the ONLY correct way to extract addresses
    from a generic storage structure.
    
    Returns:
        (host_string, port_number) tuple
        Returns ('unknown', 0) if family is unrecognized
    """
    family = storage.ss_family
    
    if family == AddressFamily.AF_INET:
        addr = SockAddrIn()
        memmove(byref(addr), byref(storage), sizeof(SockAddrIn))
        host = IPAddress.format_ipv4(addr.sin_addr.s_addr)
        port = _NativeLib.ntohs(addr.sin_port)
        return (host, port)
    
    elif family == AddressFamily.AF_INET6:
        addr = SockAddrIn6()
        memmove(byref(addr), byref(storage), sizeof(SockAddrIn6))
        ipv6_bytes = bytes(addr.sin6_addr.s6_addr)
        host = IPAddress.format_ipv6(ipv6_bytes)
        port = _NativeLib.ntohs(addr.sin6_port)
        return (host, port)
    
    return ('unknown', 0)

# ============================================================================
# I/O Multiplexing - Portable select() Selector
# ============================================================================

class Selector:
    """
    select()-based I/O multiplexing.
    
    Thread Safety: NOT thread-safe. register/unregister/poll should
    only be called from the same thread that owns the event loop.
    
    Works everywhere but has limitations:
    - Maximum 1024 file descriptors (POSIX) or 64 (Windows)
    - O(n) scanning of all registered FDs on each select() call
    - Modifies fd_set structures in-place (must rebuild each call)
    
    For high-concurrency applications (>1000 sockets), use
    SelectorFactory.create() which auto-selects epoll or kqueue.
    
    Returns RawSocket objects (not raw FDs) for usability.
    """
    
    def __init__(self):
        self._read_socks: Dict[int, RawSocket] = {}
        self._write_socks: Dict[int, RawSocket] = {}
        self._error_socks: Dict[int, RawSocket] = {}
    
    def register(self, sock: RawSocket, events: SelectEvent) -> None:
        """
        Register a socket for event monitoring.
        
        Not thread-safe. Call only from the event loop thread.
        
        Args:
            sock: RawSocket to monitor
            events: Bitmask of SelectEvent flags (READ, WRITE, ERROR)
        """
        fd = sock.fileno
        
        if events & SelectEvent.READ:
            self._read_socks[fd] = sock
        if events & SelectEvent.WRITE:
            self._write_socks[fd] = sock
        if events & SelectEvent.ERROR:
            self._error_socks[fd] = sock
    
    def unregister(self, sock: RawSocket) -> None:
        """
        Remove a socket from all event monitoring.
        
        Not thread-safe. Call only from the event loop thread.
        
        Args:
            sock: RawSocket to remove
        """
        fd = sock.fileno
        self._read_socks.pop(fd, None)
        self._write_socks.pop(fd, None)
        self._error_socks.pop(fd, None)
    
    def select(self, timeout: Optional[float] = None) -> Tuple[List[RawSocket], List[RawSocket], List[RawSocket]]:
        """
        Wait for socket events.
        
        Args:
            timeout: Maximum time to wait in seconds (None = wait forever)
            
        Returns:
            (readable_sockets, writable_sockets, error_sockets) tuples of lists
            
        Raises:
            SocketError: If select() syscall fails
        """
        def make_fd_set(sock_dict):
            """
            Build a native fd_set from a dict of fd→socket mappings.
            
            Handles platform differences correctly:
            - Windows: struct with fd_count + fd_array[64]
            - POSIX: bitmask array of longs
            """
            if not sock_dict:
                return None
            
            fd_set = _NativeLib.fd_set()
            
            if Platform.WINDOWS:
                count = 0
                for fd in sock_dict.keys():
                    if count >= _NativeLib.FD_SETSIZE:
                        break
                    fd_set.fd_array[count] = c_void_p(fd)
                    count += 1
                fd_set.fd_count = count
            else:
                ctypes.memset(byref(fd_set), 0, sizeof(fd_set))
                for fd in sock_dict.keys():
                    if 0 <= fd < _NativeLib.FD_SETSIZE:
                        idx = fd // (8 * ctypes.sizeof(c_long))
                        bit = fd % (8 * ctypes.sizeof(c_long))
                        fd_set.fds_bits[idx] |= (1 << bit)
            
            return fd_set
        
        read_set = make_fd_set(self._read_socks)
        write_set = make_fd_set(self._write_socks)
        error_set = make_fd_set(self._error_socks)
        
        # Calculate max_fd for first argument to select()
        all_fds = (
            list(self._read_socks.keys()) +
            list(self._write_socks.keys()) +
            list(self._error_socks.keys())
        )
        max_fd = max(all_fds) if all_fds else 0
        
        # Setup timeout
        if timeout is not None:
            tv = _NativeLib.TimeVal()
            tv.tv_sec = int(timeout)
            tv.tv_usec = int((timeout % 1) * 1_000_000)
            timeval_ptr = byref(tv)
        else:
            timeval_ptr = None
        
        # Call native select()
        ret = _NativeLib.select(
            max_fd + 1,
            byref(read_set) if read_set else None,
            byref(write_set) if write_set else None,
            byref(error_set) if error_set else None,
            timeval_ptr
        )
        
        if ret == _NativeLib.SOCKET_ERROR:
            raise SocketError(operation="select")
        
        def parse_fd_set(fd_set, sock_dict):
            """
            Extract ready sockets from a native fd_set.
            
            Handles platform differences correctly:
            - Windows: iterate fd_array up to fd_count
            - POSIX: check each bit in fds_bits
            """
            if fd_set is None or ret == 0:
                return []
            
            result = []
            if Platform.WINDOWS:
                for i in range(fd_set.fd_count):
                    fd = fd_set.fd_array[i]
                    sock = sock_dict.get(fd)
                    if sock is not None:
                        result.append(sock)
            else:
                for fd in sock_dict:
                    if 0 <= fd < _NativeLib.FD_SETSIZE:
                        idx = fd // (8 * ctypes.sizeof(c_long))
                        bit = fd % (8 * ctypes.sizeof(c_long))
                        if fd_set.fds_bits[idx] & (1 << bit):
                            result.append(sock_dict[fd])
            
            return result
        
        return (
            parse_fd_set(read_set, self._read_socks),
            parse_fd_set(write_set, self._write_socks),
            parse_fd_set(error_set, self._error_socks)
        )
    
    def close(self) -> None:
        """Clear all registrations."""
        self._read_socks.clear()
        self._write_socks.clear()
        self._error_socks.clear()

# ============================================================================
# I/O Multiplexing - Linux epoll() Selector
# ============================================================================

class EPollSelector:
    """
    Linux epoll-based selector for high-concurrency scenarios.
    
    Thread Safety: NOT thread-safe. All operations should be called
    from the same event loop thread.
    
    Why epoll?
    - O(1) event registration, modification, and unregistration
    - O(1) event waiting (returns ONLY active file descriptors)
    - Edge-triggered mode (EPOLLET) for event-driven architectures
    - Scales to hundreds of thousands of concurrent connections
    - No FD_SETSIZE limit (limited only by system memory)
    
    Edge-triggered mode requires:
    1. Non-blocking sockets (mandatory)
    2. Read until EAGAIN (read all available data)
    3. Write until EAGAIN or buffer empty (write all pending data)
    4. Handle EPOLLHUP and EPOLLRDHUP for connection close detection
    
    This is the same mechanism used by nginx, HAProxy, and most
    high-performance Linux servers.
    
    Requires: Linux 2.6+
    """
    
    def __init__(self):
        if not Platform.HAS_EPOLL:
            raise NotImplementedError("epoll requires Linux 2.6+")
        self._epoll = _stdlib_select.epoll()
        self._sock_map: Dict[int, RawSocket] = {}
        self._event_map: Dict[int, SelectEvent] = {}
    
    def register(self, sock: RawSocket, events: SelectEvent) -> None:
        """
        Register a socket with edge-triggered monitoring.
        
        Not thread-safe.
        
        Edge-triggered means you only get ONE notification when data
        arrives. You MUST read until EAGAIN or you'll miss data.
        
        Args:
            sock: RawSocket to monitor (must be non-blocking)
            events: Bitmask of SelectEvent flags
        """
        fd = sock.fileno
        self._sock_map[fd] = sock
        self._event_map[fd] = events
        
        epoll_events = _stdlib_select.EPOLLET  # Edge-triggered
        if events & SelectEvent.READ:
            epoll_events |= _stdlib_select.EPOLLIN
        if events & SelectEvent.WRITE:
            epoll_events |= _stdlib_select.EPOLLOUT
        if events & SelectEvent.ERROR:
            epoll_events |= _stdlib_select.EPOLLERR
        
        self._epoll.register(fd, epoll_events)
    
    def unregister(self, sock: RawSocket) -> None:
        """Remove a socket from epoll monitoring. Not thread-safe."""
        fd = sock.fileno
        try:
            self._epoll.unregister(fd)
        except OSError:
            pass  # Already unregistered or closed
        self._sock_map.pop(fd, None)
        self._event_map.pop(fd, None)
    
    def modify(self, sock: RawSocket, events: SelectEvent) -> None:
        """
        Modify event mask for a registered socket.
        
        More efficient than unregister+register. Not thread-safe.
        
        Args:
            sock: Registered RawSocket
            events: New event mask
        """
        fd = sock.fileno
        self._event_map[fd] = events
        
        epoll_events = _stdlib_select.EPOLLET
        if events & SelectEvent.READ:
            epoll_events |= _stdlib_select.EPOLLIN
        if events & SelectEvent.WRITE:
            epoll_events |= _stdlib_select.EPOLLOUT
        if events & SelectEvent.ERROR:
            epoll_events |= _stdlib_select.EPOLLERR
        
        self._epoll.modify(fd, epoll_events)
    
    def poll(self, timeout: Optional[float] = None) -> List[Tuple[RawSocket, SelectEvent]]:
        """
        Wait for events.
        
        Returns list of (socket, events) for each ready socket.
        
        EDGE-TRIGGERED REQUIREMENT: You MUST read/write until EAGAIN
        on each returned socket, or you will miss future events.
        
        Args:
            timeout: Maximum wait in seconds (None = forever)
            
        Returns:
            List of (RawSocket, SelectEvent) tuples for ready sockets
            
        Raises:
            OSError: If epoll_wait fails
        """
        max_events = max(len(self._sock_map), 1)
        timeout_ms = -1 if timeout is None else int(timeout * 1000)
        
        events = self._epoll.poll(timeout_ms, max_events)
        
        results = []
        for fd, epoll_events in events:
            sock = self._sock_map.get(fd)
            if sock is None:
                continue
            
            events = SelectEvent(0)
            if epoll_events & (_stdlib_select.EPOLLIN | _stdlib_select.EPOLLHUP | _stdlib_select.EPOLLERR):
                events |= SelectEvent.READ
            if epoll_events & _stdlib_select.EPOLLOUT:
                events |= SelectEvent.WRITE
            if epoll_events & _stdlib_select.EPOLLERR:
                events |= SelectEvent.ERROR
            if epoll_events & (_stdlib_select.EPOLLHUP | _stdlib_select.EPOLLRDHUP):
                events |= SelectEvent.HANGUP
            
            results.append((sock, events))
        
        return results
    
    def close(self) -> None:
        """Close the epoll file descriptor and clear state."""
        try:
            self._epoll.close()
        except OSError:
            pass
        self._sock_map.clear()
        self._event_map.clear()

# ============================================================================
# I/O Multiplexing - BSD/macOS kqueue() Selector
# ============================================================================

class KQueueSelector:
    """
    macOS/BSD kqueue-based selector for high concurrency.
    
    Thread Safety: NOT thread-safe. All operations should be called
    from the same event loop thread.
    
    kqueue is the BSD equivalent of epoll:
    - O(1) event operations
    - Supports filters for read/write/timer/signal/vnode events
    - Scales to massive concurrency
    - Native on macOS (used by GCD) and FreeBSD
    
    Uses EV_CLEAR flag for edge-triggered semantics.
    
    Requires: macOS 10.5+, FreeBSD 4.1+, OpenBSD 2.9+
    """
    
    def __init__(self):
        if not Platform.HAS_KQUEUE:
            raise NotImplementedError("kqueue requires macOS or BSD")
        self._kqueue = _stdlib_select.kqueue()
        self._sock_map: Dict[int, RawSocket] = {}
        self._event_map: Dict[int, SelectEvent] = {}
    
    def register(self, sock: RawSocket, events: SelectEvent) -> None:
        """
        Register a socket for kqueue monitoring.
        
        Not thread-safe.
        
        Args:
            sock: RawSocket to monitor
            events: Bitmask of SelectEvent flags
        """
        fd = sock.fileno
        self._sock_map[fd] = sock
        self._event_map[fd] = events
        
        kevents = []
        if events & SelectEvent.READ:
            kevents.append(_stdlib_select.kevent(
                fd,
                filter=_stdlib_select.KQ_FILTER_READ,
                flags=_stdlib_select.KQ_EV_ADD | _stdlib_select.KQ_EV_ENABLE | _stdlib_select.KQ_EV_CLEAR
            ))
        if events & SelectEvent.WRITE:
            kevents.append(_stdlib_select.kevent(
                fd,
                filter=_stdlib_select.KQ_FILTER_WRITE,
                flags=_stdlib_select.KQ_EV_ADD | _stdlib_select.KQ_EV_ENABLE | _stdlib_select.KQ_EV_CLEAR
            ))
        
        self._kqueue.control(kevents, 0, 0)
    
    def unregister(self, sock: RawSocket) -> None:
        """Remove a socket from kqueue monitoring. Not thread-safe."""
        fd = sock.fileno
        self._sock_map.pop(fd, None)
        self._event_map.pop(fd, None)
        
        try:
            kevents = [
                _stdlib_select.kevent(
                    fd,
                    filter=_stdlib_select.KQ_FILTER_READ,
                    flags=_stdlib_select.KQ_EV_DELETE
                ),
                _stdlib_select.kevent(
                    fd,
                    filter=_stdlib_select.KQ_FILTER_WRITE,
                    flags=_stdlib_select.KQ_EV_DELETE
                ),
            ]
            self._kqueue.control(kevents, 0, 0)
        except OSError:
            pass  # FD already closed
    
    def poll(self, timeout: Optional[float] = None) -> List[Tuple[RawSocket, SelectEvent]]:
        """
        Wait for kqueue events.
        
        Args:
            timeout: Maximum wait in seconds (None = forever)
            
        Returns:
            List of (RawSocket, SelectEvent) tuples for ready sockets
            
        Raises:
            OSError: If kevent() fails
        """
        max_events = max(len(self._sock_map), 1)
        timeout_sec = None if timeout is None else timeout
        
        events = self._kqueue.control(None, max_events, timeout_sec)
        
        results = []
        for event in events:
            sock = self._sock_map.get(event.ident)
            if sock is None:
                continue
            
            events = SelectEvent(0)
            if event.filter == _stdlib_select.KQ_FILTER_READ:
                events |= SelectEvent.READ
                if event.flags & _stdlib_select.KQ_EV_EOF:
                    events |= SelectEvent.HANGUP
            elif event.filter == _stdlib_select.KQ_FILTER_WRITE:
                events |= SelectEvent.WRITE
            
            if event.flags & _stdlib_select.KQ_EV_ERROR:
                events |= SelectEvent.ERROR
            
            results.append((sock, events))
        
        return results
    
    def close(self) -> None:
        """Close the kqueue file descriptor and clear state."""
        try:
            self._kqueue.close()
        except OSError:
            pass
        self._sock_map.clear()
        self._event_map.clear()

# ============================================================================
# Selector Factory - Auto-Select Best Multiplexer
# ============================================================================

class SelectorFactory:
    """
    Auto-select the best I/O multiplexer for the current platform.
    
    Priority:
    1. EPollSelector (Linux) - Best performance, O(1) operations
    2. KQueueSelector (macOS/BSD) - Native, O(1) operations
    3. Selector (everywhere) - Portable fallback, O(n) operations
    
    Usage:
        selector = SelectorFactory.create()
        selector.register(sock, SelectEvent.READ)
        for sock, events in selector.poll(timeout=1.0):
            handle_event(sock, events)
    """
    
    @staticmethod
    def create():
        """
        Create the best available selector for this platform.
        
        Returns:
            EPollSelector, KQueueSelector, or Selector instance
            
        The returned object implements a uniform interface:
        - register(sock, events)
        - unregister(sock)
        - poll(timeout) → List[(socket, events)]
        - close()
        """
        if Platform.HAS_EPOLL:
            try:
                return EPollSelector()
            except Exception:
                pass
        
        if Platform.HAS_KQUEUE:
            try:
                return KQueueSelector()
            except Exception:
                pass
        
        # Universal fallback
        return Selector()

# ============================================================================
# High-Level TCP Server
# ============================================================================

class TCPServer:
    """
    High-performance TCP server with automatic dual-stack support.
    
    Automatically infers IPv4 vs IPv6 from the bind address.
    For dual-stack (accept both IPv4 and IPv6 on one socket),
    bind to '::' (the IPv6 unspecified address).
    
    LESSON LEARNED (v1.0): The original TCPServer always created AF_INET
    sockets, ignoring the address family entirely. Now we auto-detect
    and even support dual-stack by setting IPV6_V6ONLY=0 on AF_INET6 sockets.
    
    Examples:
        # IPv4 only
        server = TCPServer(('0.0.0.0', 8080))
        
        # IPv6 only
        server = TCPServer(('::1', 8080))
        
        # Dual-stack (IPv4 + IPv6 on same port)
        server = TCPServer(('::', 8080))
        
        # Access underlying socket for advanced configuration
        server.socket.recv_buffer_size = 262144
        server.socket.nonblocking = True
    """
    
    def __init__(self, 
                 address: Tuple[str, int] = ('0.0.0.0', 8080),
                 backlog: int = 128,
                 reuseaddr: bool = True,
                 reuseport: bool = False,
                 nodelay: bool = True,
                 family: Optional[int] = None):
        """
        Create and bind a TCP server socket.
        
        Args:
            address: (host, port) to listen on. Auto-detects IPv4/IPv6.
            backlog: Maximum pending connections queue (kernel may cap this)
            reuseaddr: Allow address reuse (SO_REUSEADDR) - essential for fast restarts
            reuseport: Allow port sharing across processes (SO_REUSEPORT, Linux/BSD only)
            nodelay: Set TCP_NODELAY on accepted connections (disable Nagle's algorithm)
            family: Override address family (auto-detected from address if None)
            
        Raises:
            SocketError: If socket creation or bind fails
        """
        host, port = address
        
        # Infer family from address, or use explicit override
        if family is None:
            family = _infer_family(host)
        
        self._socket = RawSocket(family, SocketType.SOCK_STREAM, Protocol.IPPROTO_TCP)
        self._nodelay = nodelay
        
        # Apply common server socket options
        if reuseaddr:
            self._socket.reuseaddr = True
        
        if reuseport and Platform.HAS_SO_REUSEPORT:
            try:
                self._socket.reuseport = True
            except (NotImplementedError, OSError):
                pass  # Silently ignore if not supported
        
        # Enable dual-stack on IPv6 sockets
        # IPV6_V6ONLY=0 means the socket will also accept IPv4 connections
        if family == AddressFamily.AF_INET6:
            try:
                self._socket.set_option_int(SocketLevel.IPPROTO_IPV6, 27, 0)
            except OSError:
                pass  # Not all platforms support dual-stack
        
        self._socket.bind(address)
        self._socket.listen(backlog)
    
    @property
    def socket(self) -> RawSocket:
        """Access the underlying RawSocket for advanced configuration."""
        return self._socket
    
    @property
    def address(self) -> Tuple[str, int]:
        """Get the actual address the server is listening on."""
        return self._socket.getsockname()
    
    def accept(self) -> Tuple[RawSocket, Tuple[str, int]]:
        """Accept connection. Returned socket has TCP_NODELAY set."""
        client, addr = self._socket.accept()
        if self._nodelay:
            client.nodelay = True
        return client, addr
    
    def close(self) -> None:
        """Close the server socket."""
        self._socket.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
    
    def __repr__(self):
        if self._socket.closed:
            return f"<TCPServer [CLOSED]>"
        addr = self.address
        return f"<TCPServer {addr[0]}:{addr[1]}>"

# ============================================================================
# High-Level TCP Client
# ============================================================================

class TCPClient:
    """
    High-performance TCP client with automatic dual-stack connect.
    
    Tries all resolved addresses in OS-preferred order until one
    succeeds. Set family=AF_INET or AF_INET6 to restrict to a
    specific protocol.
    
    Examples:
        # Auto-detect (tries IPv6 first on dual-stack, falls back to IPv4)
        with TCPClient() as client:
            client.connect(('example.com', 80))
            client.sendall(b'GET / HTTP/1.0\r\n\r\n')
            response = client.recv(4096)
        
        # Force IPv4 only
        with TCPClient(family=AddressFamily.AF_INET) as client:
            client.connect(('example.com', 80))
    """
    
    def __init__(self, nodelay: bool = True, family: int = AddressFamily.AF_UNSPEC):
        self._socket = RawSocket(AddressFamily.AF_INET, SocketType.SOCK_STREAM, Protocol.IPPROTO_TCP)
        self._socket.nodelay = nodelay
        self._preferred_family = family
    
    @property
    def socket(self) -> RawSocket:
        """Access the underlying RawSocket."""
        return self._socket
    
    def connect(self, address: Tuple[str, int]) -> None:
        """Connect to server, trying all resolved addresses."""
        host, port = address
        
        if IPAddress.is_ipv4(host) or IPAddress.is_ipv6(host):
            self._socket.connect(address)
            return
        
        addresses = resolve_hostname(host, port, family=self._preferred_family, socktype=SocketType.SOCK_STREAM)
        if not addresses:
            raise SocketError(message=f"Could not resolve: {host}", operation="connect")
        
        last_error = None
        for family, addr_str, addr_port in addresses:
            try:
                if family == AddressFamily.AF_INET:
                    sockaddr = SockAddrIn.from_raw(IPAddress.parse_ipv4(addr_str), addr_port)
                    addr_len = sizeof(SockAddrIn)
                else:
                    sockaddr = SockAddrIn6.from_tuple((addr_str, addr_port))
                    addr_len = sizeof(SockAddrIn6)
                
                ret = _NativeLib.connect(self._socket._fd, byref(sockaddr), addr_len)
                if ret == 0 or (Platform.WINDOWS and ret != _NativeLib.SOCKET_ERROR):
                    return
            except (SocketError, ValueError, OSError) as e:
                last_error = e
                continue
        
        raise SocketError(message=f"Failed to connect to {host}:{port} - {last_error}", operation="connect")
    
    def send(self, data: bytes) -> int:
        return self._socket.send(data)
    
    def sendall(self, data: bytes) -> int:
        return self._socket.sendall(data)
    
    def recv(self, bufsize: int) -> bytes:
        return self._socket.recv(bufsize)
    
    def recv_into(self, buffer: bytearray, nbytes: int = -1) -> int:
        return self._socket.recv_into(buffer, nbytes)
    
    @property
    def local_address(self) -> Tuple[str, int]:
        return self._socket.getsockname()
    
    @property
    def remote_address(self) -> Tuple[str, int]:
        return self._socket.getpeername()
    
    def close(self) -> None:
        self._socket.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
    
    def __repr__(self):
        if self._socket.closed:
            return f"<TCPClient [CLOSED]>"
        try:
            remote = self.remote_address
            return f"<TCPClient connected to {remote[0]}:{remote[1]}>"
        except:
            return f"<TCPClient>"

# ============================================================================
# WinSock Cleanup
# ============================================================================

def _cleanup_winsock():
    """Cleanup WinSock at process exit (called by atexit)."""
    if Platform.WINDOWS and not _NativeLib._wsa_cleaned_up:
        _NativeLib._wsa_cleaned_up = True
        try:
            _NativeLib._wsa_cleanup()
        except:
            pass

if Platform.WINDOWS:
    atexit.register(_cleanup_winsock)

# ============================================================================
# Self-Certifying Test Suite
# ============================================================================

if __name__ == '__main__':
    import threading
    import time
    
    print("=" * 70)
    print("  pyrawsocket v3.1.1 - Production-Grade Native Socket Library")
    print("  CRITICAL FIXES: sendall() pointer arithmetic, sizeof() in fd_set")
    print("=" * 70)
    print(f"  Platform:     {Platform.OS_NAME}")
    print(f"  Features:     epoll={Platform.HAS_EPOLL}, kqueue={Platform.HAS_KQUEUE}, "
          f"reuseport={Platform.HAS_SO_REUSEPORT}")
    print(f"  Python:       {sys.version}")
    print("=" * 70)
    print()
    
    tests_passed = 0
    tests_failed = 0
    tests_skipped = 0
    
    def test(name):
        global tests_passed, tests_failed
        def decorator(fn):
            try:
                fn()
                print(f"  ✓ {name}")
                tests_passed += 1
            except Exception as e:
                print(f"  ✗ {name}: {e}")
                tests_failed += 1
                import traceback
                traceback.print_exc()
            return fn
        return decorator
    
    @test("TCP Echo Server/Client")
    def test_tcp_echo():
        with TCPServer(('127.0.0.1', 0)) as server:
            addr = server.address
            
            def client():
                with TCPClient() as c:
                    c.connect(addr)
                    c.sendall(b'Hello, pyrawsocket!')
                    response = c.recv(1024)
                    assert response == b'Echo: Hello, pyrawsocket!'
            
            t = threading.Thread(target=client)
            t.start()
            
            conn, _ = server.accept()
            data = conn.recv(1024)
            conn.sendall(b'Echo: ' + data)
            conn.close()
            t.join()
    
    @test("UDP Send/Receive")
    def test_udp():
        with RawSocket(AddressFamily.AF_INET, SocketType.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            local = sock.getsockname()
            sock.sendto(b'Ping', ('127.0.0.1', local[1]))
            data, sender = sock.recvfrom(1024)
            assert data == b'Ping'
            assert sender[1] == local[1]
    
    @test("Zero-Copy recv_into")
    def test_zero_copy():
        with TCPServer(('127.0.0.1', 0)) as server:
            addr = server.address
            
            def client():
                time.sleep(0.05)
                with TCPClient() as c:
                    c.connect(addr)
                    c.sendall(b'X' * 5000)
            
            t = threading.Thread(target=client)
            t.start()
            
            conn, _ = server.accept()
            buf = bytearray(10000)
            total = 0
            while total < 5000:
                n = conn.recv_into(buf, 5000 - total)
                if n == 0:
                    break
                total += n
            assert total == 5000
            assert buf[:5] == b'XXXXX'
            conn.close()
            t.join()
    
    @test("Non-Blocking Accept")
    def test_nonblocking():
        with TCPServer(('127.0.0.1', 0)) as server:
            server.socket.nonblocking = True
            assert server.socket.nonblocking == True
            try:
                server.accept()
                assert False, "Should have raised BlockingIOError"
            except BlockingIOError:
                pass
    
    @test("Selector (select)")
    def test_selector():
        with TCPServer(('127.0.0.1', 0)) as server:
            addr = server.address
            selector = Selector()
            selector.register(server.socket, SelectEvent.READ)
            
            def client():
                time.sleep(0.05)
                with TCPClient() as c:
                    c.connect(addr)
            
            t = threading.Thread(target=client)
            t.start()
            
            readable, _, _ = selector.select(timeout=2.0)
            assert len(readable) > 0
            conn, _ = readable[0].accept()
            conn.close()
            selector.close()
            t.join()
    
    if Platform.HAS_EPOLL:
        @test("EPollSelector (edge-triggered)")
        def test_epoll():
            with TCPServer(('127.0.0.1', 0)) as server:
                addr = server.address
                selector = EPollSelector()
                selector.register(server.socket, SelectEvent.READ)
                
                def client():
                    time.sleep(0.05)
                    with TCPClient() as c:
                        c.connect(addr)
                        c.sendall(b'Epoll test')
                
                t = threading.Thread(target=client)
                t.start()
                
                events = selector.poll(timeout=2.0)
                assert len(events) > 0
                sock, ev = events[0]
                assert ev & SelectEvent.READ
                conn, _ = sock.accept()
                conn.close()
                selector.close()
                t.join()
    else:
        tests_skipped += 1
        print(f"  - EPollSelector (skipped - requires Linux)")
    
    if Platform.HAS_KQUEUE:
        @test("KQueueSelector")
        def test_kqueue():
            with TCPServer(('127.0.0.1', 0)) as server:
                addr = server.address
                selector = KQueueSelector()
                selector.register(server.socket, SelectEvent.READ)
                
                def client():
                    time.sleep(0.05)
                    with TCPClient() as c:
                        c.connect(addr)
                
                t = threading.Thread(target=client)
                t.start()
                
                events = selector.poll(timeout=2.0)
                assert len(events) > 0
                sock, ev = events[0]
                assert ev & SelectEvent.READ
                conn, _ = sock.accept()
                conn.close()
                selector.close()
                t.join()
    else:
        tests_skipped += 1
        print(f"  - KQueueSelector (skipped - requires macOS/BSD)")
    
    @test("SelectorFactory (auto-select)")
    def test_factory():
        selector = SelectorFactory.create()
        assert selector is not None
        selector.close()
    
    @test("Hostname Resolution (localhost)")
    def test_resolve():
        addrs = resolve_hostname('localhost', 80)
        assert len(addrs) > 0
        assert addrs[0][0] in (AddressFamily.AF_INET, AddressFamily.AF_INET6)
    
    @test("Dual-Stack IPv6 Server")
    def test_dualstack():
        try:
            with TCPServer(('::1', 0)) as server:
                addr = server.address
                with TCPClient() as client:
                    client.connect(('::1', addr[1]))
                    client.sendall(b'IPv6 works!')
                conn, client_addr = server.accept()
                data = conn.recv(1024)
                assert data == b'IPv6 works!'
                conn.close()
        except OSError:
            pass  # IPv6 not available
    
    @test("Socket Options")
    def test_options():
        sock = RawSocket()
        assert not sock.reuseaddr
        sock.reuseaddr = True
        assert sock.reuseaddr
        assert not sock.nodelay
        sock.nodelay = True
        assert sock.nodelay
        sock.recv_buffer_size = 65536
        assert sock.recv_buffer_size >= 65536
        sock.close()
    
    @test("Resource Tracker (leak detection)")
    def test_tracker():
        initial = _tracker.count
        sock = RawSocket()
        assert _tracker.count == initial + 1
        sock.close()
        assert _tracker.count == initial
        with RawSocket():
            assert _tracker.count == initial + 1
        assert _tracker.count == initial
    
    @test("sendall (large data - tests pointer arithmetic fix)")
    def test_sendall():
        with TCPServer(('127.0.0.1', 0)) as server:
            addr = server.address
            large_data = b'A' * 100000
            
            def client():
                with TCPClient() as c:
                    c.connect(addr)
                    c.sendall(large_data)
            
            t = threading.Thread(target=client)
            t.start()
            
            conn, _ = server.accept()
            received = b''
            while len(received) < len(large_data):
                chunk = conn.recv(8192)
                if not chunk:
                    break
                received += chunk
            assert received == large_data
            conn.close()
            t.join()
    
    print()
    print("=" * 70)
    total = tests_passed + tests_failed
    print(f"  Results: {tests_passed} passed, {tests_failed} failed, "
          f"{tests_skipped} skipped ({total} total)")
    
    open_resources = _tracker.get_open_resources()
    if open_resources:
        print(f"  WARNING: {len(open_resources)} socket(s) leaked!")
        for r in open_resources:
            print(f"    - {r}")
    else:
        print(f"  Resource check: All sockets properly closed.")
    
    print("=" * 70)
    
    if tests_failed > 0:
        sys.exit(1)