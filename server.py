import socket
import struct
import argparse
import threading
import random
import time
import os
import logging

# ตั้งค่าการแสดงผล log
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -------------------------------
# ประเภทของ packet
# -------------------------------
TYPE_DATA = 0  # ข้อมูลปกติ
TYPE_ACK  = 1  # ACK
TYPE_EOF  = 2  # End-of-file (ไฟล์ส่งครบแล้ว)

# -------------------------------
# รูปแบบ header ของ packet
# -------------------------------
# !B I H H  -> type(1), seq(4), length(2), checksum(2)
HEADER_FMT = "!B I H H"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # ขนาด header = 9 bytes
CHUNK_SIZE = 1024  # ขนาดข้อมูลแต่ละ packet

# -------------------------------
# ฟังก์ชันคำนวณ checksum
# -------------------------------
def internet_checksum(data: bytes) -> int:
    """คำนวณ checksum ของข้อมูลเพื่อใช้ตรวจสอบความถูกต้อง"""
    if len(data) % 2 == 1:
        data += b'\x00'  # เติม 0 ถ้าข้อมูลจำนวน byte เป็นเลขคี่
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
        s = (s & 0xffff) + (s >> 16)  # เก็บ carry
    return (~s) & 0xffff  # ทำ complement เพื่อให้เป็น checksum

# -------------------------------
# ฟังก์ชันสร้าง packet
# -------------------------------
def make_packet(pkt_type: int, seq_num: int, data: bytes) -> bytes:
    """สร้าง packet พร้อม header และ checksum"""
    length = len(data)
    header_zero = struct.pack(HEADER_FMT, pkt_type, seq_num, length, 0)
    checksum = internet_checksum(header_zero + data)
    header = struct.pack(HEADER_FMT, pkt_type, seq_num, length, checksum)
    return header + data  # ส่ง header + ข้อมูล

# -------------------------------
# ฟังก์ชันแยก packet
# -------------------------------
def parse_packet(packet: bytes):
    """แยก header และข้อมูลจาก packet พร้อมตรวจสอบ checksum"""
    if len(packet) < HEADER_SIZE:
        raise ValueError("packet too small")  # packet เล็กเกินไป
    header = packet[:HEADER_SIZE]
    pkt_type, seq_num, length, checksum = struct.unpack(HEADER_FMT, header)
    data = packet[HEADER_SIZE:HEADER_SIZE+length]
    # ตรวจสอบ checksum
    header_zero = struct.pack(HEADER_FMT, pkt_type, seq_num, length, 0)
    calc = internet_checksum(header_zero + data)
    ok = (calc == checksum)
    return pkt_type, seq_num, data, ok

# -------------------------------
# ฟังก์ชันจัดการคำขอ client
# -------------------------------
def handle_client_request(client_addr, requested_filename, server_port, loss_rate, corrupt_rate):
    """รับไฟล์จาก disk แล้วส่งไปให้ client ผ่าน UDP"""
    logging.info("Handling client %s request for '%s'", client_addr, requested_filename)
    
    # ตรวจสอบว่าไฟล์มีอยู่จริงไหม
    if not os.path.exists(requested_filename):
        logging.warning("File not found: %s", requested_filename)
        return

    # สร้าง socket UDP ใหม่ สำหรับการส่งไฟล์
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))  # ใช้ ephemeral port
    sock.settimeout(1.0)  # timeout รอ ACK
    
    seq = 0  # ลำดับ packet เริ่มจาก 0
    retry_limit = 10  # จำนวนครั้งสูงสุดสำหรับ retry

    with open(requested_filename, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)  # อ่านข้อมูล 1024 bytes
            if not chunk:
                break  # ถ้า EOF ให้ออกจาก loop
            packet = make_packet(TYPE_DATA, seq, chunk)

            sent = False
            retries = 0
            while not sent:
                # จำลอง packet loss
                if random.random() < loss_rate:
                    logging.info("[SIM LOSS] Dropped packet seq=%d to %s", seq, client_addr)
                else:
                    send_packet = packet
                    # จำลอง packet corruption
                    if random.random() < corrupt_rate:
                        ba = bytearray(packet)
                        if len(ba) > HEADER_SIZE:
                            idx = HEADER_SIZE + (random.randint(0, len(ba)-HEADER_SIZE-1))
                            ba[idx] ^= 0xFF
                            send_packet = bytes(ba)
                            logging.info("[SIM CORRUPT] Corrupted packet seq=%d to %s", seq, client_addr)
                    # ส่ง packet จริง
                    sock.sendto(send_packet, client_addr)
                    logging.info("Sent seq=%d (%d bytes) to %s", seq, len(chunk), client_addr)

                # รอรับ ACK จาก client
                try:
                    data, addr = sock.recvfrom(1024)
                    pkt_type, ack_seq, _, ok = parse_packet(data)
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

    # ส่ง EOF packet เพื่อบอก client ว่าส่งไฟล์ครบแล้ว
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

# -------------------------------
# ฟังก์ชัน main สำหรับรับคำขอจาก client
# -------------------------------
def main(listen_port, loss_rate, corrupt_rate):
    """เริ่ม server UDP รอฟังคำขอจาก client"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', listen_port))
    logging.info("Server listening on UDP port %d", listen_port)
    
    while True:
        data, client_addr = sock.recvfrom(4096)
        try:
            requested = data.decode().strip()  # อ่านชื่อไฟล์ที่ client ขอ
        except Exception:
            logging.warning("Received non-decodable request from %s", client_addr)
            continue
        logging.info("Received request '%s' from %s", requested, client_addr)
        # สร้าง thread แยกเพื่อส่งไฟล์ให้ client แต่ละคน
        t = threading.Thread(target=handle_client_request, args=(client_addr, requested, listen_port, loss_rate, corrupt_rate), daemon=True)
        t.start()

# -------------------------------
# เริ่ม server
# -------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int, help="server listen port")
    parser.add_argument("--loss", type=float, default=0.0, help="simulate packet loss probability (0..1)")
    parser.add_argument("--corrupt", type=float, default=0.0, help="simulate packet corruption probability (0..1)")
    args = parser.parse_args()
    main(args.port, args.loss, args.corrupt)
