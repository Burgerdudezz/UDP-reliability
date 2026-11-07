import sys
import os
import unittest
import socket
import struct

# Ensure root path is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from streaprous_socket.streaprous_packet_struct import (
    pack_tcp_header,
    unpack_tcp_header,
    compute_tcp_checksum,
    rdt_send
)

class TestStreaprousPacketStruct(unittest.TestCase):
    
    def test_pack_and_unpack_tcp_header(self):
        src_port = 12345
        dst_port = 80
        seq = 1000
        ack_seq = 500
        offset_res = (5 << 4) + 0
        flags = 0x18  # PSH + ACK
        window = 5840
        checksum = 0xABCD
        urg_ptr = 0
        
        packed = pack_tcp_header(src_port, dst_port, seq, ack_seq, offset_res, flags, window, checksum, urg_ptr)
        self.assertEqual(len(packed), 20)
        
        unpacked = unpack_tcp_header(packed)
        self.assertEqual(unpacked['src_port'], src_port)
        self.assertEqual(unpacked['dst_port'], dst_port)
        self.assertEqual(unpacked['seq'], seq)
        self.assertEqual(unpacked['ack_seq'], ack_seq)
        self.assertEqual(unpacked['flags'], flags)
        self.assertEqual(unpacked['window'], window)
        self.assertEqual(unpacked['checksum'], checksum)
        self.assertEqual(unpacked['data_offset'], 20)

    def test_compute_tcp_checksum(self):
        src_ip = "127.0.0.1"
        dst_ip = "127.0.0.1"
        src_port = 12345
        dst_port = 80
        seq = 1
        ack_seq = 1
        offset_res = 80  # 5 << 4
        flags = 0x02  # SYN
        window = 1024
        urg_ptr = 0
        
        header_draft = pack_tcp_header(src_port, dst_port, seq, ack_seq, offset_res, flags, window, 0, urg_ptr)
        payload = b"Hello StreapRous"
        
        chk = compute_tcp_checksum(src_ip, dst_ip, header_draft, payload)
        self.assertIsInstance(chk, int)
        self.assertTrue(0 <= chk <= 0xffff)
        
        # Verify RFC 1071: computing checksum of pseudo + header (with checksum set) + payload should result in 0 (or 0xffff in one's complement check)
        header_final = pack_tcp_header(src_port, dst_port, seq, ack_seq, offset_res, flags, window, chk, urg_ptr)
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + b'\x00' + bytes([socket.IPPROTO_TCP]) + struct.pack('!H', len(header_final) + len(payload))
        total = pseudo + header_final + payload
        
        if len(total) % 2 == 1:
            total += b'\x00'
        s = 0
        for i in range(0, len(total), 2):
            s += struct.unpack('!H', total[i:i+2])[0]
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        self.assertEqual(~s & 0xffff, 0)

    def test_memoryview_fragmentation(self):
        # Mock socket for rdt_send
        class MockSocket:
            def __init__(self):
                self.sent_packets = []
            def sendto(self, packet, addr):
                self.sent_packets.append((packet, addr))
                
        sock = MockSocket()
        large_data = b"A" * 4000  # 4000 bytes, larger than MSS=1460
        
        total_sent, next_seq = rdt_send(
            sock, "127.0.0.1", "127.0.0.1", 5000, 80,
            seq=100, ack_seq=0, data=large_data,
            auto_chunk=True, mss=1460
        )
        
        self.assertEqual(total_sent, 4000)
        self.assertEqual(next_seq, 100 + 4000)
        self.assertEqual(len(sock.sent_packets), 3)  # 1460 + 1460 + 1080 = 4000 bytes

if __name__ == '__main__':
    unittest.main()

