import socket
import struct
import time

# -------------------------------
# Same as server
# -------------------------------
HEADER_FMT = "!B I H H"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
TYPE_DATA = 0
TYPE_ACK  = 1
TYPE_EOF  = 2

def internet_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def parse_packet(packet: bytes):
    if len(packet) < HEADER_SIZE:
        raise ValueError("packet too small")
    header = packet[:HEADER_SIZE]
    pkt_type, seq_num, length, checksum = struct.unpack(HEADER_FMT, header)
    data = packet[HEADER_SIZE:HEADER_SIZE+length]
    # verify checksum
    header_zero = struct.pack(HEADER_FMT, pkt_type, seq_num, length, 0)
    calc = internet_checksum(header_zero + data)
    ok = (calc == checksum)
    return pkt_type, seq_num, data, ok

def make_ack(seq_num: int) -> bytes:
    """ACK packet same format as server expects"""
    pkt_type = TYPE_ACK
    data = b""
    length = len(data)
    header_zero = struct.pack(HEADER_FMT, pkt_type, seq_num, length, 0)
    checksum = internet_checksum(header_zero + data)
    header = struct.pack(HEADER_FMT, pkt_type, seq_num, length, checksum)
    return header

# -------------------------------
# Client
# -------------------------------
def udp_file_client(server_ip: str, port: int, filename: str):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(2)

    client_socket.sendto(filename.encode(), (server_ip, port))
    print(f"Requesting file '{filename}' from {server_ip}:{port}")

    output_filename = "received_" + filename
    f = open(output_filename, "wb")

    expected_seq = 0
    while True:
        try:
            packet, addr = client_socket.recvfrom(2048)
        except socket.timeout:
            print("Timeout waiting for packet, exiting...")
            break

        pkt_type, seq_num, data, ok = parse_packet(packet)

        if pkt_type == TYPE_EOF:
            print("Received EOF, file transfer complete.")
            # send ACK for EOF
            client_socket.sendto(make_ack(seq_num), addr)
            break

        if ok and seq_num == expected_seq:
            f.write(data)
            print(f"Received packet {seq_num}, sending ACK...")
            client_socket.sendto(make_ack(seq_num), addr)
            expected_seq += 1
        else:
            print(f"Corrupted or out-of-order packet (seq={seq_num}), ignoring...")

    f.close()
    client_socket.close()
    print(f"File saved as {output_filename}")

if __name__ == "__main__":
    udp_file_client(server_ip="127.0.0.1", port=8133, filename="message.txt")
