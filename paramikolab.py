import os
import paramiko
import tkinter as tk
from tkinter import messagebox

# รายชื่อ IP Management ของอุปกรณ์ R0-R2 และ S0-S1
# สำหรับ R0 หากเข้าจาก PC นอกแล็บ ให้ใช้ IP ขา Cloud เช่น 192.168.159.129
DEVICES = [
    {"hostname": "R0", "ip": "192.168.159.129"},  # หรือ 172.31.Y.1 ถ้าอยู่ในวงเดียวกัน
    {"hostname": "S0", "ip": "172.31.2.2"},
    {"hostname": "S1", "ip": "172.31.2.3"},
    {"hostname": "R1", "ip": "172.31.2.4"},
    {"hostname": "R2", "ip": "172.31.2.5"},
]

USERNAME = "WINDOWS_USER"
KEY_PATH = os.path.expanduser("C:/Users/user002/Downloads/windows_user.ppk")

# โหลด Private Key
private_key = paramiko.RSAKey.from_private_key_file(KEY_PATH)

for dev in DEVICES:
    print(f"=== Connecting to {dev['hostname']} ({dev['ip']}) ===")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # เชื่อมต่อโดยใช้ Public Key Authentication (ไม่ส่ง password)
        ssh.connect(
            hostname=dev["ip"],
            username=USERNAME,
            pkey=private_key,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )

        # รันคำสั่งทดสอบ
        stdin, stdout, stderr = ssh.exec_command("show ip interface brief")
        print(stdout.read().decode())

    except Exception as e:
        print(f"Failed to connect to {dev['hostname']}: {e}")
    finally:
        ssh.close()

# ---------------------------------------------------------
# เพิ่ม Feature: แสดง GUI Popup เมื่อรันเสร็จ
# ---------------------------------------------------------
root = tk.Tk()
root.withdraw()  # ซ่อนหน้าต่างหลัก (จะได้มีแค่กล่องข้อความเด้งขึ้นมา)
messagebox.showinfo("Status", "Finished Run")
root.destroy()   # ปิดการทำงานของหน้าต่างเมื่อกด OK
