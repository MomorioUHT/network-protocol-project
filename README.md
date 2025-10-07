### Network 01418351 Protocol UDP Project
---
- Natthadit Phaungthongthip 6610450161
- Tontawan Janthai 6610450951
- Rungrisa Rueangsri 6610451079

# UDP File Transfer

โปรแกรมนี้เป็นตัวอย่างการส่งไฟล์ผ่าน **UDP** แบบง่าย ๆ พร้อมการตรวจสอบ **checksum** และ **ACK** เพื่อให้รับประกันความถูกต้องของข้อมูล แม้จะเกิด **packet loss** หรือ **corruption** ขึ้น

---

## 📂 ไฟล์ในโปรเจกต์

- `server.py` : โปรแกรม Server สำหรับส่งไฟล์  
- `client.py` : โปรแกรม Client สำหรับดาวน์โหลดไฟล์  
- `example.txt` : ตัวอย่างไฟล์ที่ต้องการส่ง

---

## 1️⃣ การเตรียมไฟล์

1. วางไฟล์ที่ต้องการส่ง (`example.txt`) ไว้ในโฟลเดอร์เดียวกับ `server.py`  
2. ตรวจสอบว่าไฟล์ `server.py` และ `client.py` อยู่ใน Directory เดียวกัน

---

## 2️⃣ รัน Server

```bash
python server.py <port> [--loss <loss_rate>] [--corrupt <corrupt_rate>]
```
* \<port\> : พอร์ต UDP ที่ server จะฟัง เช่น 8133
* --loss : ความน่าจะเป็นของ packet loss (0..1)
* --corrupt : ความน่าจะเป็นของ packet corruption (0..1)
ตัวอย่าง
```bash
python server.py 8133 --loss 0.05 --corrupt 0.1
```

---

## 3️⃣ รัน Client

```bash
python client.py <server_ip> <port> <filename>
```
* \<server_ip\> : IP ของเครื่องที่รัน server (ถ้าเครื่องเดียวกันใช้ 127.0.0.1)
* \<port\> : พอร์ตเดียวกับที่ server ฟัง
* \<filename\> : ชื่อไฟล์ที่ต้องการดาวน์โหลดจาก server
ตัวอย่าง
```bash
python client.py 127.0.0.1 8133 example.txt
```

## 4️⃣ การทดสอบ

4.1 ทดสอบเบื้องต้น (ไม่มี loss/corrupt)
```bash
python server.py 8133
python client.py 127.0.0.1 8133 example.txt
```
* ควรได้ไฟล์ received_example.txt เหมือนกับ example.txt
* Console log จะแสดง packet ทั้งหมดที่ส่งและ ACK

4.2 ทดสอบกับ packet loss
```bash
python server.py 8133 --loss 0.2
python client.py 127.0.0.1 8133 example.txt
```
* Server จะ drop packet บางส่วน (20%)
* Client จะ timeout แล้ว retry จนได้รับทุก packet

4.3 ทดสอบกับ packet corruption
```bash
python server.py 8133 --corrupt 0.1
python client.py 127.0.0.1 8133 example.txt
```
* บาง packet จะถูกแก้ไข
* Client จะตรวจสอบ checksum และ ละเว้น packet ที่เสียหาย
* Server จะส่ง packet ซ้ำจน client ได้ครบ

4.4 ทดสอบ EOF และ retry
* Server ส่ง EOF packet เป็น packet สุดท้าย
* Client ส่ง ACK ให้ EOF
* หาก packet หรือ ACK ของ EOF หาย server จะ retry จนถึง retry_limit

5️⃣ Workflow ของโปรแกรม

1. Client ส่ง ชื่อไฟล์ ไปยัง server
2. Server อ่านไฟล์เป็น chunks ขนาด 1024 bytes
3. Server ทำ packet (header + checksum + data) และส่ง packet ทีละ sequence
4. Client ตรวจสอบ checksum + sequence
    * ถูกต้อง → บันทึกและส่ง ACK
    * ผิด → ละเว้น, server จะ retry

5. Server ส่ง EOF หลังส่งไฟล์เสร็จ
6. Client ส่ง ACK สำหรับ EOF
7. การส่งไฟล์เสร็จสมบูรณ์

---