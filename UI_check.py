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
        with open(file_path, "rb") as file:
            public_key_data = file.read()
        public_key_text.config(state=tk.NORMAL)
        public_key_text.delete("1.0", tk.END)
        public_key_text.insert(tk.END, public_key_data.decode(errors='ignore') or "Chưa có nội dung")
        public_key_text.config(state=tk.DISABLED)

def load_message():
    global message_data
    file_path = filedialog.askopenfilename(filetypes=[("Thông điệp", "*.*")])
    if file_path:
        with open(file_path, "rb") as file:
            message_data = file.read()
        message_text.config(state=tk.NORMAL)
        message_text.delete("1.0", tk.END)
        message_text.insert(tk.END, message_data.decode(errors='ignore') or "Chưa có nội dung")
        message_text.config(state=tk.DISABLED)

def load_signature():
    global signature_data
    file_path = filedialog.askopenfilename(filetypes=[("Chữ ký", "*.*")])
    if file_path:
        with open(file_path, "rb") as file:
            signature_data = file.read()
        signature_text.config(state=tk.NORMAL)
        signature_text.delete("1.0", tk.END)
        signature_text.insert(tk.END, signature_data.hex() or "Chưa có nội dung")
        signature_text.config(state=tk.DISABLED)

def verify_signature():
    global public_key_data, message_data, signature_data
    if not (public_key_data and message_data and signature_data):
        messagebox.showerror("Lỗi", "Vui lòng chọn đủ 3 tệp: khóa công khai, thông điệp và chữ ký")
        return
    
    try:
        public_key = RSA.import_key(public_key_data)
        hash_obj = SHA256.new(message_data)
        decoded_hash = SHA256.new()
        pkcs1_15.new(public_key).verify(hash_obj, signature_data)
        decoded_hash.update(message_data)
        
        hash_original_text.config(state=tk.NORMAL)
        hash_original_text.delete("1.0", tk.END)
        hash_original_text.insert(tk.END, hash_obj.hexdigest())
        hash_original_text.config(state=tk.DISABLED)
        
        hash_decoded_text.config(state=tk.NORMAL)
        hash_decoded_text.delete("1.0", tk.END)
        hash_decoded_text.insert(tk.END, decoded_hash.hexdigest())
        hash_decoded_text.config(state=tk.DISABLED)
        
        messagebox.showinfo("Kết quả", "Chữ ký hợp lệ, không bị thay đổi!")
    except (ValueError, TypeError):
        messagebox.showerror("Kết quả", "Chữ ký không hợp lệ hoặc bị thay đổi!")

def create_gui():
    global public_key_text, message_text, signature_text, hash_original_text, hash_decoded_text
    root = tk.Tk()
    root.title("Kiểm tra chữ ký số")
    root.geometry("600x550")
    
    tk.Label(root, text="Chọn tệp để kiểm tra chữ ký số", font=("Arial", 12)).pack(pady=10)
    
    tk.Button(root, text="Chọn khóa công khai", command=load_public_key).pack(pady=5)
    public_key_text = tk.Text(root, height=3, width=70, state=tk.DISABLED)
    public_key_text.pack(pady=5)
    
    tk.Button(root, text="Chọn thông điệp", command=load_message).pack(pady=5)
    message_text = tk.Text(root, height=3, width=70, state=tk.DISABLED)
    message_text.pack(pady=5)
    
    tk.Button(root, text="Chọn chữ ký", command=load_signature).pack(pady=5)
    signature_text = tk.Text(root, height=3, width=70, state=tk.DISABLED)
    signature_text.pack(pady=5)
    
    tk.Button(root, text="Xác minh chữ ký", command=verify_signature).pack(pady=10)
    
    tk.Label(root, text="Giá trị băm của thông điệp gốc:").pack(pady=5)
    hash_original_text = tk.Text(root, height=2, width=70, state=tk.DISABLED)
    hash_original_text.pack(pady=5)
    
    tk.Label(root, text="Giá trị băm giải mã từ chữ ký:").pack(pady=5)
    hash_decoded_text = tk.Text(root, height=2, width=70, state=tk.DISABLED)
    hash_decoded_text.pack(pady=5)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
