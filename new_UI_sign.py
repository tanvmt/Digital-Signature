import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, PublicFormat, NoEncryption
import os

global public_key_data, private_key_data, message_data, signature_data
public_key_data = None
private_key_data = None
message_data = None
signature_data = None

def get_next_key_index():
    index = 1
    while os.path.exists(f"private_key_{index}.key") or os.path.exists(f"public_key_{index}.key"):
        index += 1
    return index

def load_key(file_type, textbox, label, is_private_key=False):
    file_path = filedialog.askopenfilename(filetypes=[(file_type, "*.*")])
    if file_path:
        with open(file_path, "rb") as file:
            key_data = file.read()
        
        # Load private key if it's a private key file
        if is_private_key:
            global private_key_data
            private_key_data = key_data
        else:
            global public_key_data
            public_key_data = key_data
        
        textbox.delete("1.0", tk.END)
        textbox.insert(tk.END, key_data.decode())
        label.config(text=f"Đã tải: {os.path.basename(file_path)}")
    else:
        textbox.delete("1.0", tk.END)
        textbox.insert(tk.END, "Chưa có khóa")

def generate_keys():
    global public_key_data, private_key_data
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key_data = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    public_key_data = key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    index = get_next_key_index()
    private_key_filename = f"private_key_{index}.key"
    public_key_filename = f"public_key_{index}.key"
    
    with open(private_key_filename, "wb") as file:
        file.write(private_key_data)
    with open(public_key_filename, "wb") as file:
        file.write(public_key_data)
    
    private_key_textbox.delete("1.0", tk.END)
    private_key_textbox.insert(tk.END, private_key_data.decode())
    private_key_label.config(text=f"Đã lưu: {private_key_filename}")
    
    public_key_textbox.delete("1.0", tk.END)
    public_key_textbox.insert(tk.END, public_key_data.decode())
    public_key_label.config(text=f"Đã lưu: {public_key_filename}")
    
    messagebox.showinfo("Thành công", f"Đã tạo khóa công khai và khóa riêng tư!\nLưu tại: {public_key_filename}, {private_key_filename}")

def save_message():
    global message_data
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(message_entry.get())
        messagebox.showinfo("Thành công", f"Thông điệp đã được lưu tại: {os.path.basename(file_path)}")

def sign_message():
    global private_key_data, message_data, signature_data
    if private_key_data is None:
        messagebox.showerror("Lỗi", "Vui lòng tạo hoặc chọn khóa riêng tư trước!")
        return
    
    message_data = message_entry.get().encode()
    hash_obj = hashes.Hash(hashes.SHA256())
    hash_obj.update(message_data)
    digest = hash_obj.finalize()

    private_key = load_pem_private_key(private_key_data, password=None) 

    signature_data = private_key.sign(
        digest,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    signature_filename = "signature.pem"
    with open(signature_filename, "wb") as file:
        file.write(signature_data)
    
    signature_textbox.delete("1.0", tk.END)
    signature_textbox.insert(tk.END, signature_data.hex())
    messagebox.showinfo("Thành công", f"Đã ký thông điệp thành công!\nChữ ký lưu tại: {signature_filename}")

def create_gui():
    global message_entry, signature_textbox, public_key_textbox, private_key_textbox, public_key_label, private_key_label
    root = tk.Tk()
    root.title("Hệ thống ký số")
    root.geometry("600x600")
    
    tk.Label(root, text="Tạo hoặc tải khóa RSA", font=("Arial", 12)).pack(pady=5)
    tk.Button(root, text="Tạo khóa công khai và khóa riêng tư", command=generate_keys).pack(pady=5)
    
    
    tk.Button(root, text="Tải khóa công khai", command=lambda: load_key("Khóa công khai", public_key_textbox, public_key_label)).pack(pady=5)
    public_key_label = tk.Label(root, text="Chưa có khóa công khai")
    public_key_label.pack()
    public_key_textbox = tk.Text(root, height=5, width=70)
    public_key_textbox.insert(tk.END, "Chưa có khóa")
    public_key_textbox.pack(pady=5)
    
    
    tk.Button(root, text="Tải khóa riêng tư", command=lambda: load_key("Khóa riêng tư", private_key_textbox, private_key_label, is_private_key=True)).pack(pady=5)
    private_key_label = tk.Label(root, text="Chưa có khóa riêng tư")
    private_key_label.pack()
    private_key_textbox = tk.Text(root, height=5, width=70)
    private_key_textbox.insert(tk.END, "Chưa có khóa")
    private_key_textbox.pack(pady=5)
    
    tk.Label(root, text="Nhập thông điệp để ký", font=("Arial", 12)).pack(pady=5)
    message_entry = tk.Entry(root, width=50)
    message_entry.pack(pady=5)
    
    tk.Button(root, text="Lưu thông điệp", command=save_message).pack(pady=5)
    tk.Button(root, text="Ký số", command=sign_message).pack(pady=5)
    
    signature_textbox = tk.Text(root, height=5, width=70)
    signature_textbox.insert(tk.END, "Chưa có chữ ký số")
    signature_textbox.pack(pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
