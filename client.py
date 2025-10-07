import socket
import struct
import time
import sys

# -------------------------------
# กำหนดรูปแบบ packet ให้ตรงกับ server
# -------------------------------
# HEADER_FMT = "!B I H H" แปลว่า
# B = unsigned char (1 byte) สำหรับ type
# I = unsigned int (4 bytes) สำหรับ sequence number
# H = unsigned short (2 bytes) สำหรับความยาวข้อมูล
# H = unsigned short (2 bytes) สำหรับ checksum
HEADER_FMT = "!B I H H"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # ขนาด header รวมทั้งหมด
TYPE_DATA = 0  # ประเภทข้อมูลปกติ
TYPE_ACK  = 1  # ประเภท ACK
TYPE_EOF  = 2  # ประเภท end-of-file (จบไฟล์)

# -------------------------------
# ฟังก์ชันคำนวณ checksum แบบ Internet
# -------------------------------
def internet_checksum(data: bytes) -> int:
    """คำนวณ checksum ของข้อมูลเพื่อใช้ตรวจสอบความถูกต้อง"""
    if len(data) % 2 == 1:
        data += b'\x00'  # ถ้าเป็นเลขคี่ เติม 0 ต่อท้าย
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]  # เอา 2 bytes มารวมเป็น 16 bit
        s += w
        s = (s & 0xffff) + (s >> 16)  # เก็บ carry
    return (~s) & 0xffff  # ทำ complement เพื่อให้เป็น checksum

# -------------------------------
# ฟังก์ชันแยก packet
# -------------------------------
def parse_packet(packet: bytes):
    """รับ packet เข้ามา แยก header และข้อมูล พร้อมตรวจสอบ checksum"""
    if len(packet) < HEADER_SIZE:
        raise ValueError("packet too small")  # ถ้า packet เล็กเกินไป
    header = packet[:HEADER_SIZE]
    pkt_type, seq_num, length, checksum = struct.unpack(HEADER_FMT, header)
    data = packet[HEADER_SIZE:HEADER_SIZE+length]

    # ตรวจสอบ checksum
    header_zero = struct.pack(HEADER_FMT, pkt_type, seq_num, length, 0)
    calc = internet_checksum(header_zero + data)
    ok = (calc == checksum)  # True ถ้า checksum ถูกต้อง
    return pkt_type, seq_num, data, ok

# -------------------------------
# ฟังก์ชันสร้าง ACK
# -------------------------------
def make_ack(seq_num: int) -> bytes:
    """สร้าง packet ACK เพื่อส่งกลับ server"""
    pkt_type = TYPE_ACK
    data = b""  # ACK ไม่มีข้อมูล
    length = len(data)
    # คำนวณ checksum
    header_zero = struct.pack(HEADER_FMT, pkt_type, seq_num, length, 0)
    checksum = internet_checksum(header_zero + data)
    # รวม header พร้อม checksum
    header = struct.pack(HEADER_FMT, pkt_type, seq_num, length, checksum)
    return header

# -------------------------------
# ฟังก์ชันหลัก client
# -------------------------------
def udp_file_client(server_ip: str, port: int, filename: str):
    """ดาวน์โหลดไฟล์จาก server ผ่าน UDP"""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # สร้าง socket UDP
    client_socket.settimeout(2)  # ตั้งเวลา timeout 2 วินาที

    # ส่งชื่อไฟล์ไปขอจาก server
    client_socket.sendto(filename.encode(), (server_ip, port))
    print(f"Requesting file '{filename}' from {server_ip}:{port}")

    output_filename = "received_" + filename  # ตั้งชื่อไฟล์ที่จะบันทึก
    f = open(output_filename, "wb")  # เปิดไฟล์สำหรับเขียน binary

    expected_seq = 0  # ลำดับ packet ที่คาดว่าจะได้รับ
    while True:
        try:
            packet, addr = client_socket.recvfrom(2048)  # รับ packet ขนาดสูงสุด 2048 bytes
        except socket.timeout:
            print("Timeout waiting for packet, exiting...")
            break  # ถ้า timeout ให้หยุดการรับ

        pkt_type, seq_num, data, ok = parse_packet(packet)  # แยก packet

        if pkt_type == TYPE_EOF:
            # ถ้าเจอ EOF แสดงว่าไฟล์ส่งครบแล้ว
            print("Received EOF, file transfer complete.")
            client_socket.sendto(make_ack(seq_num), addr)  # ส่ง ACK สุดท้าย
            break

        if ok and seq_num == expected_seq:
            # ถ้า packet ถูกต้อง และเป็นลำดับที่เราคาดไว้
            f.write(data)  # เขียนข้อมูลลงไฟล์
            print(f"Received packet {seq_num}, sending ACK...")
            client_socket.sendto(make_ack(seq_num), addr)  # ส่ง ACK กลับ server
            expected_seq += 1  # คาดหมายลำดับถัดไป
        else:
            # ถ้า packet เสียหายหรือมาลำดับผิด
            print(f"Corrupted or out-of-order packet (seq={seq_num}), ignoring...")

    f.close()
    client_socket.close()
    print(f"File saved as {output_filename}")

# -------------------------------
# Main: รับ argument จาก command line
# -------------------------------
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python client.py <server_ip> <port> <filename>")
        sys.exit(1)

    server_ip = sys.argv[1]
    port = int(sys.argv[2])
    filename = sys.argv[3]

    udp_file_client(server_ip, port, filename)
