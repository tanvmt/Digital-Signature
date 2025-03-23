import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

global public_key_data, message_data, signature_data
public_key_data = None
message_data = None
signature_data = None

def load_public_key():
    global public_key_data
    file_path = filedialog.askopenfilename(filetypes=[("Khóa công khai", "*.*")])
    if file_path:
        public_key_label.config(text=f"Đã chọn: {file_path}")
        with open(file_path, "rb") as file:
            public_key_data = file.read()

def load_message():
    global message_data
    file_path = filedialog.askopenfilename(filetypes=[("Thông điệp", "*.*")])
    if file_path:
        message_label.config(text=f"Đã chọn: {file_path}")
        with open(file_path, "rb") as file:
            message_data = file.read()

def load_signature():
    global signature_data
    file_path = filedialog.askopenfilename(filetypes=[("Chữ ký", "*.*")])
    if file_path:
        signature_label.config(text=f"Đã chọn: {file_path}")
        with open(file_path, "rb") as file:
            signature_data = file.read()

def verify_signature():
    global public_key_data, message_data, signature_data
    if not (public_key_data and message_data and signature_data):
        messagebox.showerror("Lỗi", "Vui lòng chọn đủ 3 tệp: khóa công khai, thông điệp và chữ ký")
        return
    
    try:
        public_key = RSA.import_key(public_key_data)
        hash_obj = SHA256.new(message_data)
        pkcs1_15.new(public_key).verify(hash_obj, signature_data)
        messagebox.showinfo("Kết quả", "Chữ ký hợp lệ, không bị thay đổi!")
    except (ValueError, TypeError):
        messagebox.showerror("Kết quả", "Chữ ký không hợp lệ hoặc bị thay đổi!")

def create_gui():
    global public_key_label, message_label, signature_label
    root = tk.Tk()
    root.title("Kiểm tra chữ ký số")
    root.geometry("500x300")
    
    tk.Label(root, text="Chọn tệp để kiểm tra chữ ký số", font=("Arial", 12)).pack(pady=10)
    
    tk.Button(root, text="Chọn khóa công khai", command=load_public_key).pack()
    public_key_label = tk.Label(root, text="Chưa chọn tệp")
    public_key_label.pack()
    
    tk.Button(root, text="Chọn thông điệp", command=load_message).pack()
    message_label = tk.Label(root, text="Chưa chọn tệp")
    message_label.pack()
    
    tk.Button(root, text="Chọn chữ ký", command=load_signature).pack()
    signature_label = tk.Label(root, text="Chưa chọn tệp")
    signature_label.pack()
    
    tk.Button(root, text="Xác minh chữ ký", command=verify_signature).pack(pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
