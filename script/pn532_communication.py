"""
PN532 Communication Interface
Abstract communication interface, supports serial, TCP, UDP, etc.
"""
import socket
import threading
import time
import queue
from abc import ABC, abstractmethod
from typing import Union, Optional
import serial
import re

class CommunicationInterface(ABC):
    """Abstract communication interface"""
    
    @abstractmethod
    def is_open(self) -> bool:
        """Check if the connection is open"""
        pass
    
    @abstractmethod
    def open(self, address: str) -> bool:
        """Open the connection"""
        pass
    
    @abstractmethod
    def close(self) -> None:
        """Close the connection"""
        pass
    
    @abstractmethod
    def write(self, data: bytes) -> int:
        """Write data"""
        pass
    
    @abstractmethod
    def read(self, size: int = 1) -> bytes:
        """Read data"""
        pass
    
    @abstractmethod
    def set_timeout(self, timeout: float) -> None:
        """Set timeout"""
        pass
    
    @abstractmethod
    def get_connection_info(self) -> str:
        """Get connection information string"""
        pass

class SerialCommunication(CommunicationInterface):
    """Serial communication implementation"""
    
    def __init__(self):
        self.serial_instance: Optional[serial.Serial] = None
        
    def is_open(self) -> bool:
        return self.serial_instance is not None and self.serial_instance.is_open
    
    def open(self, address: str) -> bool:
        try:
            self.serial_instance = serial.Serial(port=address, baudrate=115200)
            self.serial_instance.dtr = False
            self.serial_instance.rts = False
            return True
        except Exception as e:
            print(f"Serial connection failed: {e}")
            return False
    
    def close(self) -> None:
        if self.serial_instance:
            self.serial_instance.close()
            self.serial_instance = None
    
    def write(self, data: bytes) -> int:
        if self.serial_instance:
            return self.serial_instance.write(data)
        return 0
    
    def read(self, size: int = 1) -> bytes:
        if self.serial_instance:
            return self.serial_instance.read(size)
        return b''
    
    def set_timeout(self, timeout: float) -> None:
        if self.serial_instance:
            self.serial_instance.timeout = timeout
    
    def get_connection_info(self) -> str:
        """Get serial connection information"""
        if self.serial_instance and self.serial_instance.is_open:
            return f"Serial: {self.serial_instance.port}"
        return "Serial: Not connected"

class TCPCommunication(CommunicationInterface):
    """TCP communication implementation"""
    
    def __init__(self):
        self.socket_instance: Optional[socket.socket] = None
        self.timeout = 5.0  # Increase timeout to 5 seconds
        
    def is_open(self) -> bool:
        """Check if TCP connection is still active"""
        if self.socket_instance is None:
            return False
        
        try:
            # Try to get peer name to check if connection is still active
            self.socket_instance.getpeername()
            return True
        except (OSError, socket.error):
            # Connection is broken, cleanup
            self.socket_instance.close()
            self.socket_instance = None
            return False
    
    def open(self, address: str) -> bool:
        try:
            # Parse address format: host:port
            host, port = address.rsplit(':', 1)
            port = int(port)
            
            self.socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket_instance.settimeout(self.timeout)
            self.socket_instance.connect((host, port))
            return True
        except Exception as e:
            print(f"TCP connection failed: {e}")
            return False
    
    def close(self) -> None:
        if self.socket_instance:
            self.socket_instance.close()
            self.socket_instance = None
    
    def write(self, data: bytes) -> int:
        if self.socket_instance:
            try:
                self.socket_instance.send(data)
                return len(data)
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                print(f"TCP connection lost during write: {e}")
                self.socket_instance.close()
                self.socket_instance = None
                return 0
            except Exception as e:
                print(f"TCP write failed: {e}")
                return 0
        return 0
    
    def read(self, size: int = 1) -> bytes:
        if self.socket_instance:
            try:
                data = self.socket_instance.recv(size)
                if len(data) == 0:
                    # Remote side closed the connection
                    print("TCP connection closed by remote")
                    self.socket_instance.close()
                    self.socket_instance = None
                    return b''
                return data
            except socket.timeout:
                return b''
            except (ConnectionResetError, OSError) as e:
                print(f"TCP connection lost during read: {e}")
                self.socket_instance.close()
                self.socket_instance = None
                return b''
            except Exception as e:
                print(f"TCP read failed: {e}")
                return b''
        return b''
    
    def set_timeout(self, timeout: float) -> None:
        self.timeout = timeout
        if self.socket_instance:
            self.socket_instance.settimeout(timeout)
    
    def get_connection_info(self) -> str:
        """Get TCP connection information"""
        if self.socket_instance:
            try:
                local = self.socket_instance.getsockname()
                remote = self.socket_instance.getpeername()
                return f"TCP: {local[0]}:{local[1]} -> {remote[0]}:{remote[1]}"
            except:
                return "TCP: Connected but unable to get info"
        return "TCP: Not connected"

class UDPCommunication(CommunicationInterface):
    """UDP communication implementation"""
    
    def __init__(self):
        self.socket_instance: Optional[socket.socket] = None
        self.server_address: Optional[tuple] = None
        self.timeout = 1.0
        self.connection_failed_count = 0  # Track failed operations
        self.max_failed_count = 3  # Max failures before considering disconnected
        
    def is_open(self) -> bool:
        """Check if UDP connection is still usable"""
        if self.socket_instance is None:
            return False
        
        # For UDP, we consider it "open" if socket exists and failed count is below threshold
        if self.connection_failed_count >= self.max_failed_count:
            print("UDP connection considered failed after multiple errors")
            self.close()
            return False
            
        return True
    
    def open(self, address: str) -> bool:
        try:
            # Parse address format: host:port
            host, port = address.rsplit(':', 1)
            port = int(port)
            
            self.socket_instance = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket_instance.settimeout(self.timeout)
            self.server_address = (host, port)
            
            # UDP is connectionless, but we can send a test packet to verify connection
            test_data = b'\x00\x00\xFF\x00\xFF\x00'  # PN532 test frame
            self.socket_instance.sendto(test_data, self.server_address)
            
            return True
        except Exception as e:
            print(f"UDP connection failed: {e}")
            return False
    
    def close(self) -> None:
        if self.socket_instance:
            self.socket_instance.close()
            self.socket_instance = None
            self.server_address = None
        self.connection_failed_count = 0  # Reset failed count
    
    def write(self, data: bytes) -> int:
        if self.socket_instance and self.server_address:
            try:
                self.socket_instance.sendto(data, self.server_address)
                self.connection_failed_count = 0  # Reset on successful operation
                return len(data)
            except (OSError, socket.error) as e:
                print(f"UDP write failed: {e}")
                self.connection_failed_count += 1
                return 0
            except Exception as e:
                print(f"UDP write failed: {e}")
                self.connection_failed_count += 1
                return 0
        return 0
    
    def read(self, size: int = 1) -> bytes:
        # 对于 UDP, 使用较大缓冲防止帧被截断，并尝试读取多个datagram
        if self.socket_instance:
            try:
                # 先读取第一个UDP包
                data, addr = self.socket_instance.recvfrom(512)
                self.connection_failed_count = 0  # Reset on successful operation
                
                # 立即尝试读取更多UDP包（非阻塞），但要更谨慎
                original_timeout = self.socket_instance.gettimeout()
                try:
                    self.socket_instance.settimeout(0.001)  # 很短的超时，1ms
                    for _ in range(3):  # 减少到最多3个包
                        try:
                            more_data, _ = self.socket_instance.recvfrom(512)
                            if more_data:  # 只有非空数据才添加
                                data += more_data
                        except (socket.timeout, BlockingIOError, OSError):
                            break  # 没有更多包了
                except Exception:
                    pass  # 忽略所有异常
                finally:
                    self.socket_instance.settimeout(original_timeout)  # 恢复原timeout
                
                return data
            except socket.timeout:
                return b''
            except (OSError, socket.error) as e:
                print(f"UDP read failed: {e}")
                self.connection_failed_count += 1
                return b''
            except Exception as e:
                print(f"UDP read failed: {e}")
                self.connection_failed_count += 1
                return b''
        return b''
    
    def set_timeout(self, timeout: float) -> None:
        self.timeout = timeout
        if self.socket_instance:
            self.socket_instance.settimeout(timeout)
    
    def get_connection_info(self) -> str:
        """Get UDP connection information"""
        if self.socket_instance and self.server_address:
            local = self.socket_instance.getsockname()
            return f"UDP: {local[0]}:{local[1]} -> {self.server_address[0]}:{self.server_address[1]}"
        return "UDP: Not connected"

class CommunicationFactory:
    """Communication interface factory class"""
    
    @staticmethod
    def create_communication(address: str) -> CommunicationInterface:
        """
        Create corresponding communication interface according to address format
        
        Supported formats:
        - tcp:192.168.1.100:1234 - TCP connection
        - udp:192.168.1.100:2345 - UDP connection
        - /dev/ttyUSB0 or COM3 - Serial connection
        """
        if address.startswith('tcp:'):
            tcp_address = address[4:]  # Remove 'tcp:' prefix
            return TCPCommunication()
        elif address.startswith('udp:'):
            udp_address = address[4:]  # Remove 'udp:' prefix
            return UDPCommunication()
        else:
            # Default to serial connection
            return SerialCommunication()
    
    @staticmethod
    def parse_address(address: str) -> tuple[str, str]:
        """
        Parse address, return (protocol type, actual address)
        """
        if address.startswith('tcp:'):
            return 'tcp', address[4:]
        elif address.startswith('udp:'):
            return 'udp', address[4:]
        else:
            return 'serial', address
