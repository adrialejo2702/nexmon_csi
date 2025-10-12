"""
readpcap.py

Python class to read PCAP files for CSI data extraction
Equivalent to readpcap.m MATLAB class
"""

import struct
import numpy as np


class ReadPcap:
    """
    Class to read PCAP files
    """
    
    def __init__(self):
        self.fid = None
        self.global_header = {}
        self.file_position = 0
    
    def open(self, filename):
        """
        Open PCAP file and read global header
        
        Parameters:
        -----------
        filename : str
            Path to PCAP file
        """
        self.fid = open(filename, 'rb')
        
        # Read global header (24 bytes total)
        # Magic number (4 bytes)
        self.global_header['magic_number'] = struct.unpack('I', self.fid.read(4))[0]
        
        # Version major (2 bytes)
        self.global_header['version_major'] = struct.unpack('H', self.fid.read(2))[0]
        
        # Version minor (2 bytes)
        self.global_header['version_minor'] = struct.unpack('H', self.fid.read(2))[0]
        
        # GMT to local correction (4 bytes, signed)
        self.global_header['thiszone'] = struct.unpack('i', self.fid.read(4))[0]
        
        # Accuracy of timestamps (4 bytes)
        self.global_header['sigfigs'] = struct.unpack('I', self.fid.read(4))[0]
        
        # Max length of captured packets (4 bytes)
        self.global_header['snaplen'] = struct.unpack('I', self.fid.read(4))[0]
        
        # Data link type (4 bytes)
        self.global_header['network'] = struct.unpack('I', self.fid.read(4))[0]
        
        self.file_position = 24
    
    def next(self):
        """
        Read next frame from PCAP file
        
        Returns:
        --------
        frame : dict or None
            Dictionary with 'header' and 'payload' keys, or None if no more frames
        """
        if self.fid is None:
            return None
        
        frame = {'header': {}, 'payload': None}
        
        # Read packet header (16 bytes total)
        # Timestamp seconds (4 bytes)
        data = self.fid.read(4)
        if len(data) < 4:
            return None
        frame['header']['ts_sec'] = struct.unpack('I', data)[0]
        
        # Timestamp microseconds (4 bytes)
        frame['header']['ts_usec'] = struct.unpack('I', self.fid.read(4))[0]
        
        # Number of octets saved in file (4 bytes)
        frame['header']['incl_len'] = struct.unpack('I', self.fid.read(4))[0]
        
        # Actual length of packet (4 bytes)
        frame['header']['orig_len'] = struct.unpack('I', self.fid.read(4))[0]
        
        incl_len = frame['header']['incl_len']
        
        # Read payload
        if incl_len % 4 == 0:
            # Read as uint32
            payload_data = self.fid.read(incl_len)
            frame['payload'] = np.frombuffer(payload_data, dtype=np.uint32)
        else:
            # Read as uint8
            payload_data = self.fid.read(incl_len)
            frame['payload'] = np.frombuffer(payload_data, dtype=np.uint8)
        
        self.file_position += 16 + incl_len
        
        return frame
    
    def from_start(self):
        """
        Seek back to start of packets (after global header)
        """
        if self.fid is not None:
            self.fid.seek(24)
            self.file_position = 24
    
    def all(self):
        """
        Read all frames from PCAP file
        
        Returns:
        --------
        frames : list
            List of all frames in the file
        """
        frames = []
        self.from_start()
        
        while True:
            frame = self.next()
            if frame is None:
                break
            frames.append(frame)
        
        return frames
    
    def close(self):
        """
        Close the PCAP file
        """
        if self.fid is not None:
            self.fid.close()
            self.fid = None
    
    def __del__(self):
        """
        Destructor to ensure file is closed
        """
        self.close()

