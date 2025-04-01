import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes

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
        public_key_label.config(text=f"Đã tải khóa công khai: {file_path.split('/')[-1]}")  # Hiển thị tên file

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
        message_label.config(text=f"Đã tải thông điệp: {file_path.split('/')[-1]}")  # Hiển thị tên file

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
        signature_label.config(text=f"Đã tải chữ ký: {file_path.split('/')[-1]}")  # Hiển thị tên file

def verify_signature():
    global public_key_data, message_data, signature_data
    if not (public_key_data and message_data and signature_data):
        messagebox.showerror("Lỗi", "Vui lòng chọn đủ 3 tệp: khóa công khai, thông điệp và chữ ký")
        return

    try:
        public_key = load_pem_public_key(public_key_data)

        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(message_data)
        digest = hasher.finalize()

        public_key.verify(
            signature_data,
            digest,      
            padding.PKCS1v15(),
            hashes.SHA256()   
        )

        # Display hashes
        hash_original_text.config(state=tk.NORMAL)
        hash_original_text.delete("1.0", tk.END)
        hash_original_text.insert(tk.END, digest.hex()) # Hiển thị hash tính được
        hash_original_text.config(state=tk.DISABLED)

        messagebox.showinfo("Kết quả", "Chữ ký hợp lệ, không bị thay đổi!")
    except Exception as e:
        # Tính toán và hiển thị hash gốc ngay cả khi lỗi để dễ debug
        try:
            hash_obj_display = hashes.Hash(hashes.SHA256())
            hash_obj_display.update(message_data)
            digest_display = hash_obj_display.finalize()
            hash_original_text.config(state=tk.NORMAL)
            hash_original_text.delete("1.0", tk.END)
            hash_original_text.insert(tk.END, f"Hash gốc (lỗi xác minh): {digest_display.hex()}")
            hash_original_text.config(state=tk.DISABLED)
        except: # Nếu không có message_data thì bỏ qua
             pass
        messagebox.showerror("Kết quả", f"Chữ ký không hợp lệ hoặc bị thay đổi!\n{str(e)}")

def create_gui():
    global public_key_text, message_text, signature_text, hash_original_text, public_key_label, message_label, signature_label
    root = tk.Tk()
    root.title("Kiểm tra chữ ký số")
    root.geometry("600x600")
    
    tk.Label(root, text="Chọn tệp để kiểm tra chữ ký số", font=("Arial", 12)).pack(pady=10)
    
    tk.Button(root, text="Chọn khóa công khai", command=load_public_key).pack(pady=5)
    public_key_label = tk.Label(root, text="Chưa có khóa công khai", font=("Arial", 10))
    public_key_label.pack(pady=5)
    public_key_text = tk.Text(root, height=3, width=70, state=tk.DISABLED)
    public_key_text.pack(pady=5)
    
    
    tk.Button(root, text="Chọn thông điệp", command=load_message).pack(pady=5)
    message_label = tk.Label(root, text="Chưa có thông điệp", font=("Arial", 10))
    message_label.pack(pady=5)
    message_text = tk.Text(root, height=3, width=70, state=tk.DISABLED)
    message_text.pack(pady=5)
    
    
    tk.Button(root, text="Chọn chữ ký", command=load_signature).pack(pady=5)
    signature_label = tk.Label(root, text="Chưa có chữ ký", font=("Arial", 10))
    signature_label.pack(pady=5)
    signature_text = tk.Text(root, height=3, width=70, state=tk.DISABLED)
    signature_text.pack(pady=5)
    
    
    tk.Button(root, text="Xác minh chữ ký", command=verify_signature).pack(pady=10)
    
    tk.Label(root, text="Giá trị băm của thông điệp gốc:").pack(pady=5)
    hash_original_text = tk.Text(root, height=2, width=70, state=tk.DISABLED)
    hash_original_text.pack(pady=5)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
