import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

global public_key_data, private_key_data, message_data, signature_data
public_key_data = None
private_key_data = None
message_data = None
signature_data = None

def load_key(file_type, textbox):
    file_path = filedialog.askopenfilename(filetypes=[(file_type, "*.*")])
    if file_path:
        with open(file_path, "rb") as file:
            key_data = file.read()
        textbox.delete("1.0", tk.END)
        textbox.insert(tk.END, key_data.decode())
    else:
        textbox.delete("1.0", tk.END)
        textbox.insert(tk.END, "Chưa có khóa")

def generate_keys():
    global public_key_data, private_key_data
    key = RSA.generate(1024)
    private_key_data = key.export_key()
    public_key_data = key.publickey().export_key()
    
    with open("private.key", "wb") as file:
        file.write(private_key_data)
    with open("public.key", "wb") as file:
        file.write(public_key_data)
    
    private_key_textbox.delete("1.0", tk.END)
    private_key_textbox.insert(tk.END, private_key_data.decode())
    
    public_key_textbox.delete("1.0", tk.END)
    public_key_textbox.insert(tk.END, public_key_data.decode())
    
    messagebox.showinfo("Thành công", "Đã tạo khóa công khai và khóa riêng tư!")

def save_message():
    global message_data
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(message_entry.get())
        messagebox.showinfo("Thành công", "Thông điệp đã được lưu!")

def sign_message():
    global private_key_data, message_data, signature_data
    if private_key_data is None:
        messagebox.showerror("Lỗi", "Vui lòng tạo hoặc chọn khóa riêng tư trước!")
        return
    
    message_data = message_entry.get().encode()
    hash_obj = SHA256.new(message_data)
    private_key = RSA.import_key(private_key_data)
    signature_data = pkcs1_15.new(private_key).sign(hash_obj)
    
    with open("signature.pem", "wb") as file:
        file.write(signature_data)
    
    signature_label.config(text=f"Chữ ký số: {signature_data.hex()}")
    messagebox.showinfo("Thành công", "Đã ký thông điệp thành công!")

def create_gui():
    global message_entry, signature_label, public_key_textbox, private_key_textbox
    root = tk.Tk()
    root.title("Hệ thống ký số và kiểm tra chữ ký")
    root.geometry("600x600")
    
    tk.Label(root, text="Tạo hoặc tải khóa RSA", font=("Arial", 12)).pack(pady=5)
    tk.Button(root, text="Tạo khóa công khai và khóa riêng tư", command=generate_keys).pack(pady=5)
    
    tk.Button(root, text="Tải khóa công khai", command=lambda: load_key("Khóa công khai", public_key_textbox)).pack(pady=5)
    public_key_textbox = tk.Text(root, height=5, width=70)
    public_key_textbox.insert(tk.END, "Chưa có khóa")
    public_key_textbox.pack(pady=5)
    
    tk.Button(root, text="Tải khóa riêng tư", command=lambda: load_key("Khóa riêng tư", private_key_textbox)).pack(pady=5)
    private_key_textbox = tk.Text(root, height=5, width=70)
    private_key_textbox.insert(tk.END, "Chưa có khóa")
    private_key_textbox.pack(pady=5)
    
    tk.Label(root, text="Nhập thông điệp để ký", font=("Arial", 12)).pack(pady=5)
    message_entry = tk.Entry(root, width=50)
    message_entry.pack(pady=5)
    
    tk.Button(root, text="Lưu thông điệp", command=save_message).pack(pady=5)
    tk.Button(root, text="Ký số", command=sign_message).pack(pady=5)
    
    signature_label = tk.Label(root, text="Chưa có chữ ký số", font=("Arial", 10))
    signature_label.pack(pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
