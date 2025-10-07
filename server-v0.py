#!/usr/bin/env python3
import socket
import struct
import argparse
import threading
import random
import time
import os
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Packet types
TYPE_DATA = 0
TYPE_ACK  = 1
TYPE_EOF  = 2

HEADER_FMT = "!B I H H"   # type(1), seq(4), length(2), checksum(2)
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 9 bytes

def internet_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def make_packet(pkt_type: int, seq_num: int, data: bytes) -> bytes:
    length = len(data)
    # header with checksum=0
    header_zero = struct.pack(HEADER_FMT, pkt_type, seq_num, length, 0)
    checksum = internet_checksum(header_zero + data)
    header = struct.pack(HEADER_FMT, pkt_type, seq_num, length, checksum)
    return header + data

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

def handle_client_request(client_addr, requested_filename, server_port, loss_rate, corrupt_rate, chunk_size):
    logging.info("Handling client %s request for '%s'", client_addr, requested_filename)
    if not os.path.exists(requested_filename):
        logging.warning("File not found: %s", requested_filename)
        return
    # create a new socket for this transfer (ephemeral port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))  # let OS pick ephemeral port
    sock.settimeout(1.0)  # retransmit timeout
    seq = 0
    retry_limit = 10

    with open(requested_filename, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            packet = make_packet(TYPE_DATA, seq, chunk)

            sent = False
            retries = 0
            while not sent:
                # simulate loss
                if random.random() < loss_rate:
                    logging.info("[SIM LOSS] Dropped packet seq=%d to %s", seq, client_addr)
                else:
                    # simulate corruption
                    send_packet = packet
                    if random.random() < corrupt_rate:
                        ba = bytearray(packet)
                        # flip one byte in data region if exists
                        if len(ba) > HEADER_SIZE:
                            idx = HEADER_SIZE + (random.randint(0, len(ba)-HEADER_SIZE-1))
                            ba[idx] ^= 0xFF
                            send_packet = bytes(ba)
                            logging.info("[SIM CORRUPT] Corrupted packet seq=%d to %s", seq, client_addr)
                    sock.sendto(send_packet, client_addr)
                    logging.info("Sent seq=%d (%d bytes) to %s", seq, len(chunk), client_addr)

                # wait for ACK
                try:
                    data, addr = sock.recvfrom(1024)
                    # parse ack
                    try:
                        pkt_type, ack_seq, _, ok = parse_packet(data)
                    except Exception:
                        logging.warning("Malformed ACK from %s", addr)
                        continue
                    if pkt_type == TYPE_ACK and ok and ack_seq == seq:
                        logging.info("Received ACK %d from %s", ack_seq, addr)
                        sent = True
                        seq += 1
                    else:
                        logging.info("Received unexpected ACK/type/cksum (type=%s, seq=%s, ok=%s)", pkt_type, ack_seq, ok)
                except socket.timeout:
                    retries += 1
                    logging.warning("Timeout waiting for ACK %d (retry %d/%d)", seq, retries, retry_limit)
                    if retries >= retry_limit:
                        logging.error("Retries exceeded for seq %d; aborting transfer to %s", seq, client_addr)
                        sock.close()
                        return
                    # else loop to resend

    # send EOF and wait for ACK of EOF
    eof_packet = make_packet(TYPE_EOF, seq, b'')
    retries = 0
    while True:
        if random.random() < loss_rate:
            logging.info("[SIM LOSS] Dropped EOF to %s", client_addr)
        else:
            sock.sendto(eof_packet, client_addr)
            logging.info("Sent EOF seq=%d to %s", seq, client_addr)
        try:
            data, addr = sock.recvfrom(1024)
            pkt_type, ack_seq, _, ok = parse_packet(data)
            if pkt_type == TYPE_ACK and ok and ack_seq == seq:
                logging.info("Received ACK for EOF from %s", addr)
                break
        except socket.timeout:
            retries += 1
            logging.warning("Timeout waiting for ACK of EOF (retry %d)", retries)
            if retries >= retry_limit:
                logging.error("Retries exceeded for EOF; aborting.")
                break

    sock.close()
    logging.info("Finished transfer to %s", client_addr)

def main(listen_port, loss_rate, corrupt_rate, chunk_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', listen_port))
    logging.info("Server listening on UDP port %d", listen_port)
    while True:
        data, client_addr = sock.recvfrom(4096)
        # Expect client to send filename as a simple string request
        try:
            requested = data.decode().strip()
        except Exception:
            logging.warning("Received non-decodable request from %s", client_addr)
            continue
        logging.info("Received request '%s' from %s", requested, client_addr)
        # spawn new thread to handle transfer
        t = threading.Thread(target=handle_client_request, args=(client_addr, requested, listen_port, loss_rate, corrupt_rate, chunk_size), daemon=True)
        t.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int, help="server listen port")
    parser.add_argument("--loss", type=float, default=0.0, help="simulate packet loss probability (0..1)")
    parser.add_argument("--corrupt", type=float, default=0.0, help="simulate packet corruption probability (0..1)")
    parser.add_argument("--chunk", type=int, default=1024, help="data chunk size (bytes)")
    args = parser.parse_args()
    main(args.port, args.loss, args.corrupt, args.chunk)
