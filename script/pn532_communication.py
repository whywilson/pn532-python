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

class TCPCommunication(CommunicationInterface):
    """TCP communication implementation"""
    
    def __init__(self):
        self.socket_instance: Optional[socket.socket] = None
        self.timeout = 5.0  # Increase timeout to 5 seconds
        
    def is_open(self) -> bool:
        return self.socket_instance is not None
    
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
            except Exception as e:
                print(f"TCP write failed: {e}")
                return 0
        return 0
    
    def read(self, size: int = 1) -> bytes:
        if self.socket_instance:
            try:
                return self.socket_instance.recv(size)
            except socket.timeout:
                return b''
            except Exception as e:
                print(f"TCP read failed: {e}")
                return b''
        return b''
    
    def set_timeout(self, timeout: float) -> None:
        self.timeout = timeout
        if self.socket_instance:
            self.socket_instance.settimeout(timeout)

class UDPCommunication(CommunicationInterface):
    """UDP communication implementation"""
    
    def __init__(self):
        self.socket_instance: Optional[socket.socket] = None
        self.server_address: Optional[tuple] = None
        self.timeout = 1.0
        
    def is_open(self) -> bool:
        return self.socket_instance is not None
    
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
    
    def write(self, data: bytes) -> int:
        if self.socket_instance and self.server_address:
            try:
                self.socket_instance.sendto(data, self.server_address)
                return len(data)
            except Exception as e:
                print(f"UDP write failed: {e}")
                return 0
        return 0
    
    def read(self, size: int = 1) -> bytes:
        if self.socket_instance:
            try:
                data, addr = self.socket_instance.recvfrom(size)
                return data
            except socket.timeout:
                return b''
            except Exception as e:
                print(f"UDP read failed: {e}")
                return b''
        return b''
    
    def set_timeout(self, timeout: float) -> None:
        self.timeout = timeout
        if self.socket_instance:
            self.socket_instance.settimeout(timeout)

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
