from streaprous_socket.streaprous_raw_connection import (
    connections, connections_lock, build_tcp_packet, build_ip_header,pack_tcp_header, unpack_tcp_header, compute_tcp_checksum,conn_struct
)
from streaprous_socket.streaprous_packet_dispatcher import get_packet_queue, remove_packet_queue

import socket
import struct
import time
import queue
from collections import namedtuple
reorder_buffers = {} 
def reliable_send( sock, src_ip, dest_ip, src_port, dst_port, seq, ack_seq,
        payload, auto_chunk=True, mss=1460, flags=0x18, window=5840):
    """sends data reliably over a TCP-like connection using a custom implementation of the TCP protocol.
    Args:
            sock      (socket.socket): Raw socket instance
            src_ip    (str): Source IP address
            dest_ip   (str): Destination IP address
            src_port  (int): Source port
            dst_port  (int): Destination port
            seq       (int): Initial sequence number
            ack_seq   (int): Acknowledgement number
            payload   (bytes or bytearray): Data payload to transmit
            auto_chunk(bool): If True, automatically fragment data into mss-sized chunks
            mss       (int): Maximum Segment Size (default: 1460 bytes)
            flags     (int): TCP flags (default: 0x18 -> PSH + ACK)
            window    (int): TCP window size (default: 5840)
            
        Returns:
            tuple: (total_sent, next_seq)"""
    from streaprous_socket.streaprous_raw_connection import build_ip_header

    if not isinstance(payload, (bytes, bytearray, memoryview)):
            payload = payload.encode('utf-8') if isinstance(payload, str) else bytes(payload)

    data_mv = memoryview(payload)
    total_sent = 0
    current_seq = seq
    pkt_queue= get_packet_queue((dest_ip, dst_port))  # Retrieve the global packet queue

    if not auto_chunk or len(data_mv) <= mss:
        chunks = [data_mv]
    else:
        chunks = [data_mv[i:i + mss] for i in range(0, len(data_mv), mss)]
            
    offset_res = (5 << 4) + 0
    urg_ptr = 0
    
    for chunk in chunks:
        chunk_bytes = chunk.tobytes()
        
        # 1. Build draft TCP header with checksum = 0
        draft_tcp_header = pack_tcp_header(
            src_port, dst_port, current_seq, ack_seq,
            offset_res, flags, window, 0, urg_ptr
        )
        
        # 2. Compute RFC 1071 Checksum with Pseudo-IP Header
        tcp_checksum = compute_tcp_checksum(src_ip, dest_ip, draft_tcp_header, chunk_bytes)
        
        # 3. Build final TCP header with valid checksum
        tcp_header = pack_tcp_header(
            src_port, dst_port, current_seq, ack_seq,
            offset_res, flags, window, tcp_checksum, urg_ptr
        )
        
        # 4. Build IP header
        ip_header = build_ip_header(src_ip, dest_ip, socket.IPPROTO_TCP, len(tcp_header) + len(chunk_bytes))
        
        # 5. Assemble full packet
        full_packet = ip_header + tcp_header + chunk_bytes
        
        # 6. Transmit via Raw Socket
        timeout = 1.0  # Timeout in seconds
        expected_ack = current_seq + len(chunk_bytes)   # client should reply with this
        retries = 0
        

        while True:
            sock.sendto(full_packet, (dest_ip, 0))
            dup_acks = 0
            print(f"[Streap_RDT] Sent chunk seq={current_seq}, waiting for ack={expected_ack}")

            acked = False
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    packet, _ = pkt_queue.get(timeout=max(0, deadline - time.time()))
                except queue.Empty:
                    break                                   # timer ran out

                ihl = (packet[0] & 0x0F) * 4                # skip IP header
                tcp = unpack_tcp_header(packet[ihl:])
                if tcp['flags'] & 0x10:
                    if tcp['ack_seq'] >= expected_ack:
                        acked = True
                        break
                if tcp['ack_seq'] == current_seq:      # client still asking for this chunk
                    dup_acks += 1
                    if dup_acks >= 3:
                        print(f"[Streap_RDT] 3 dup ACKs for seq={current_seq}, fast retransmit")
                        break                           # leave early -> outer loop resends

                # any other packet (old ACK, etc.): ignore and keep waiting

            if acked:
                break

            retries += 1
            if retries > 10:
                raise ConnectionError(f"no ACK for seq={current_seq} after 10 retries")
            #print(f"[Streap_RDT] Timeout for seq={current_seq}, resending ({retries})")

        total_sent += len(chunk_bytes)
        current_seq += len(chunk_bytes)
        
    print(f"[Streap_RDT] Sent {len(chunks)} chunk(s), total {total_sent} bytes, next_seq={current_seq}")
    return total_sent, current_seq
            

#Time out handling for streaprous reliability

#Retransmission when 3 acknowledgements of the same ack_num are received.

#Reciver's handling of out of order packets.
def reliable_receive(s: socket.socket, conn_info: conn_struct) -> bytes:
    """
        Receive data on an established connection using raw sockets.
        This function handles incoming packets for a specific connection by reading
        from the packet dispatcher's per-connection queue.
        
        Args:
            s: raw socket
            conn_info: conn_struct tuple for the connection
        
        Returns:
            bytes: The received data payload, or empty bytes if connection closed
    """
    client_ip = conn_info.client_ip
    client_port = conn_info.client_port
    client_key = (client_ip, client_port)
    listen_ip = conn_info.server_ip
    listen_port = conn_info.server_port
    
        
        # Get the packet queue for this connection from the dispatcher
    packet_queue = get_packet_queue(client_key)
        
    print(f"[Streap_raw] run_conn_recv: Starting receive loop for {client_ip}:{client_port} (waiting for data...)")
        
    try:
        while True:
            # Get packet from the dispatcher queue instead of reading directly from socket
            try:
                packet, addr = packet_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            # Extract IP Header Length
            ihl = (packet[0] & 0x0F) * 4
            tcp_packet = packet[ihl:]
            
            if len(tcp_packet) < 20:
                continue

            # Unpack the received TCP header
            tcph = struct.unpack('!HHLLBBHHH', tcp_packet[:20])
            src_port, dest_port, pkt_seq, pkt_ack, flags = (
                tcph[0],
                tcph[1],
                tcph[2],
                tcph[3],
                tcph[5],
            )

            # Bypass non-listen port
            if dest_port != listen_port:
                continue

            # Check if this packet is for our connection
            if src_port != client_port:
                continue
            
            syn_flag = (flags & 0x02) >> 1
            ack_flag = (flags & 0x10) >> 4
            psh_flag = (flags & 0x08) >> 3
            fin_flag = (flags & 0x01)
            rst_flag = (flags & 0x04) >> 2

            print(f"[Streap_raw] run_conn_recv: Received packet from {client_ip}:{client_port} (SYN={syn_flag}, ACK={ack_flag}, PSH={psh_flag}, FIN={fin_flag}, RST={rst_flag}, Seq={pkt_seq}, Ack={pkt_ack})")

            with connections_lock:
                if client_key not in connections:
                    continue
                session = connections[client_key]

            # Handle FIN (connection close)
            if fin_flag:
                print(f"[Streap_raw] Received FIN from {client_ip}:{client_port}")
                # Send ACK for FIN
                ack_packet = build_tcp_packet(listen_ip, client_ip, listen_port, client_port,
                                                seq=session.server_seq, ack_seq=pkt_seq + 1, ack=1)
                ip_header = build_ip_header(listen_ip, client_ip, socket.IPPROTO_TCP, len(ack_packet))
                s.sendto(ip_header + ack_packet, (client_ip, 0))
                
                with connections_lock:
                    if client_key in connections:
                        del connections[client_key]
                # Clean up packet queue
                remove_packet_queue(client_key)
                return b""

            # Handle RST (connection reset)
            if rst_flag:
                print(f"[Streap_raw] Received RST from {client_ip}:{client_port}")
                with connections_lock:
                    if client_key in connections:
                        del connections[client_key]
                # Clean up packet queue
                remove_packet_queue(client_key)
                reorder_buffers.pop(client_key, None)
                return b""

            # Update last activity
            with connections_lock:
                if client_key in connections:
                    connections[client_key] = session._replace(last_activity=time.time())

            # Handle data payload (PSH + ACK) or (ACK with data) - Fast path ACK
            # Some clients may not set PSH flag for small requests
            has_data = len(tcp_packet) > ((tcp_packet[12] >> 4) & 0x0F) * 4
            
            if (psh_flag and ack_flag) or (ack_flag and has_data and not syn_flag and not fin_flag and not rst_flag):
                # Dynamically look up header length to bypass any incoming TCP Options
                tcp_header_len = ((tcp_packet[12] >> 4) & 0x0F) * 4
                app_payload = tcp_packet[tcp_header_len:]
                
                if len(app_payload) > 0:
                    expected = session.client_seq
                    buf = reorder_buffers.setdefault(client_key, {})
                    data = b""

                    if pkt_seq == expected:                 # in order -> deliver + pull from buffer
                        data = app_payload
                        expected += len(app_payload)
                        while expected in buf:
                            nxt = buf.pop(expected)
                            data += nxt
                            expected += len(nxt)
                    elif pkt_seq > expected:                # gap -> hold it
                        buf[pkt_seq] = app_payload
                        print(f"[Streap_RDT] Out of order seq={pkt_seq}, want {expected}, buffered")
                    else:                                   # old duplicate -> drop
                        print(f"[Streap_RDT] Duplicate seq={pkt_seq}, ignored")

                    # Always ACK the next byte we want (cumulative ACK)
                    ack_packet = build_tcp_packet(session.server_ip, client_ip, listen_port, client_port,
                                                  seq=session.server_seq, ack_seq=expected, ack=1)
                    ip_header = build_ip_header(session.server_ip, client_ip, socket.IPPROTO_TCP, len(ack_packet))
                    s.sendto(ip_header + ack_packet, (client_ip, 0))

                    with connections_lock:
                        if client_key in connections:
                            connections[client_key] = session._replace(
                                client_seq=expected, last_activity=time.time())

                    if data:
                        return data
                    # nothing deliverable yet -> fall through and keep looping


            # Handle pure ACK (no data)
            elif ack_flag and not syn_flag and not psh_flag and not has_data:
                print(f"[Streap_raw] Received ACK from {client_ip}:{client_port} (Ack={pkt_ack})")
                with connections_lock:
                    if client_key in connections:
                        connections[client_key] = session._replace(
                            server_seq=pkt_ack,
                            last_activity=time.time()
                        )

    except KeyboardInterrupt:
        print("\n[Streap_raw] Receive loop interrupted.")
        return b""
    except Exception as e:
        print(f"[Streap_raw] Error in run_conn_recv: {e}")
        return b""