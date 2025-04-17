import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import os
import datetime
import pytz 

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_private_key(filename, password):
    """Tạo và lưu trữ khóa bí mật RSA."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Mã hóa nếu có mật khẩu
    encryption_algo = serialization.NoEncryption()
    if password:
        encryption_algo=serialization.BestAvailableEncryption(password.encode('utf-8'))

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    )
    with open(filename, "wb") as f:
        f.write(pem)
    return private_key

def load_private_key(filename, password):
    """Tải khóa bí mật từ file."""
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password.encode('utf-8') if password else None,
            backend=default_backend()
        )
    return private_key

def load_public_key_from_cert(cert_filename):
    """Tải khóa công khai từ file chứng thư."""
    cert = load_certificate(cert_filename) # Reuse load_certificate
    if cert:
        return cert.public_key()
    return None


def load_certificate(filename):
    """Tải chứng thư từ file."""
    try:
        with open(filename, "rb") as cert_file:
            cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
        return cert
    except FileNotFoundError:
        # log_message(f"Lỗi: Không tìm thấy file chứng thư: {filename}")
        print(f"Lỗi: Không tìm thấy file chứng thư: {filename}") # Log to console if logger not available yet
        return None
    except Exception as e:
        # log_message(f"Lỗi khi tải chứng thư {filename}: {e}")
        print(f"Lỗi khi tải chứng thư {filename}: {e}") # Log to console
        return None


def create_self_signed_ca_cert(ca_key, ca_cert_filename, country, state, locality, org_name, common_name):
    """Tạo chứng thư số tự ký cho CA."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Lấy múi giờ UTC để chuẩn hóa
    now_utc = datetime.datetime.now(pytz.utc)

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now_utc - datetime.timedelta(days=1) # Hợp lệ từ hôm qua
    ).not_valid_after(
        # Hợp lệ trong 5 năm
        now_utc + datetime.timedelta(days=5*365)
    ).add_extension( # Đánh dấu đây là CA
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    # Thêm KeyUsage cho CA (có thể ký cert khác)
    ).add_extension(
        x509.KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False),
        critical=True
    ).sign(ca_key, hashes.SHA256(), default_backend()) # Thuật toán hash mặc định khi ký cert

    with open(ca_cert_filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def create_csr(user_key, country, state, locality, org_name, common_name):
    """Tạo Yêu cầu Cấp chứng thư (CSR)."""
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    # Yêu cầu cấp chứng thư được ký bằng khóa bí mật của người dùng
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject_name
    ).sign(user_key, hashes.SHA256(), default_backend())
    return csr

def sign_csr(csr, ca_key, ca_cert, user_cert_filename):
    """CA ký vào CSR để tạo chứng thư cho người dùng."""
    # Lấy múi giờ UTC
    now_utc = datetime.datetime.now(pytz.utc)

    builder = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject # Issuer là CA
    ).public_key(
        csr.public_key() # Public key lấy từ CSR
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now_utc - datetime.timedelta(days=1)
    ).not_valid_after(
        # Hợp lệ trong 1 năm
        now_utc + datetime.timedelta(days=365)
    )
    # Thêm các extension cần thiết cho end-user certificate
    # Ví dụ: KeyUsage cho chữ ký số và mã hóa key (tùy mục đích)
    builder = builder.add_extension(
         x509.KeyUsage(key_cert_sign=False, crl_sign=False, digital_signature=True, content_commitment=True, key_encipherment=True, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False),
         critical=True
     )
    # Thêm BasicConstraints cho biết đây không phải là CA
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    # Có thể thêm SubjectAlternativeName (SAN) nếu cần
    # builder = builder.add_extension(x509.SubjectAlternativeName([...]), critical=False)
    # Có thể thêm ExtendedKeyUsage (ví dụ: serverAuth, clientAuth)
    # builder = builder.add_extension(x509.ExtendedKeyUsage([...]), critical=False)

    # Ký chứng thư bằng khóa bí mật của CA
    user_cert = builder.sign(ca_key, hashes.SHA256(), default_backend())

    with open(user_cert_filename, "wb") as f:
        f.write(user_cert.public_bytes(serialization.Encoding.PEM))
    return user_cert


def sign_data(data, private_key_filename, password):
    """Ký dữ liệu bằng khóa bí mật."""
    try:
        private_key = load_private_key(private_key_filename, password)
        signature = private_key.sign(
            data,
            padding.PSS( # Nên dùng PSS padding
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256() # Thuật toán hash
        )
        return signature
    except FileNotFoundError:
        raise FileNotFoundError(f"Không tìm thấy file khóa bí mật: {private_key_filename}")
    except ValueError as e: # Thường là sai mật khẩu
        if "Decryption failed" in str(e):
             raise ValueError("Sai mật khẩu khóa bí mật hoặc file khóa bị lỗi.")
        else:
             raise ValueError(f"Lỗi khi tải khóa bí mật: {e}")
    except Exception as e:
        raise Exception(f"Lỗi không xác định khi ký dữ liệu: {e}")


def verify_signature(data, signature, signer_cert_filename, ca_cert_filename):
    """Xác thực chữ ký và chuỗi chứng thư. Trả về (bool, message)"""
    log_messages_verify = [] # List to hold messages during verification

    def log_verify(msg):
        log_messages_verify.append(msg)
        print(msg) # Also print to console for debugging

    log_verify("\n--- Bắt đầu Xác thực Chữ ký ---")
    try:
        # 1. Tải chứng thư của người ký và CA
        log_verify(f"Đang tải chứng thư người ký: {signer_cert_filename}")
        signer_cert = load_certificate(signer_cert_filename)
        if not signer_cert: return False, "\n".join(log_messages_verify) + f"\n!!! LỖI: Không thể tải chứng thư người ký {signer_cert_filename}"

        log_verify(f"Đang tải chứng thư CA: {ca_cert_filename}")
        ca_cert = load_certificate(ca_cert_filename)
        if not ca_cert: return False, "\n".join(log_messages_verify) + f"\n!!! LỖI: Không thể tải chứng thư CA {ca_cert_filename}"

        # 2. Kiểm tra tính hợp lệ về thời gian của chứng thư người ký
        log_verify("Kiểm tra thời hạn chứng thư người ký...")
        now_utc = datetime.datetime.now(pytz.utc) # Sử dụng UTC
        if now_utc < signer_cert.not_valid_before_utc or now_utc > signer_cert.not_valid_after_utc:
             msg = f"!!! LỖI: Chứng thư người ký không hợp lệ về thời gian (Valid from {signer_cert.not_valid_before_utc} to {signer_cert.not_valid_after_utc}, Now is {now_utc})"
             log_verify(msg)
             return False, "\n".join(log_messages_verify) + "\n" + "Chứng thư hết hạn hoặc chưa có hiệu lực"
        log_verify("-> Thời hạn chứng thư người ký: OK")

        # 3. Kiểm tra xem chứng thư người ký có được cấp bởi CA đã biết không
        log_verify("Kiểm tra chuỗi tin cậy (chứng thư người ký có được CA ký không)...")
        try:
            ca_public_key = ca_cert.public_key()
            # Kiểm tra chữ ký của signer_cert bằng public key của ca_cert
            ca_public_key.verify(
                 signer_cert.signature,
                 signer_cert.tbs_certificate_bytes, # Dữ liệu cần ký để tạo cert
                 # Padding và hash algorithm phải khớp với lúc CA ký cert
                 # Thư viện cryptography tự động phát hiện từ cert nếu có thể,
                 # nhưng chỉ định rõ ràng PKCS1v15 thường an toàn hơn cho cert signature verification.
                 padding.PKCS1v15(),
                 signer_cert.signature_hash_algorithm, # Lấy hash algorithm từ cert
            )
            # Kiểm tra Issuer của signer_cert phải là Subject của ca_cert
            if signer_cert.issuer != ca_cert.subject:
                raise ValueError("Issuer của chứng thư người ký không khớp với Subject của CA.")

            log_verify("-> Chuỗi tin cậy (Người ký <- CA): OK")
        except ValueError as e: # Thêm bắt lỗi ValueError
            msg = f"!!! LỖI: Chuỗi tin cậy không hợp lệ. {e}"
            log_verify(msg)
            return False, "\n".join(log_messages_verify) + "\n" + "Chứng thư không được cấp bởi CA tin cậy hoặc thông tin không khớp."
        except Exception as e: # Bắt các lỗi verify khác
            msg = f"!!! LỖI: Không thể xác minh chữ ký của CA trên chứng thư người ký. {e}"
            log_verify(msg)
            return False, "\n".join(log_messages_verify) + "\n" + "Chứng thư không được cấp bởi CA tin cậy hoặc bị lỗi."


        # 4. Xác thực chữ ký trên dữ liệu bằng khóa công khai của người ký
        log_verify("Kiểm tra chữ ký trên dữ liệu...")
        signer_public_key = signer_cert.public_key()
        try:
            signer_public_key.verify(
                signature,
                data,
                padding.PSS( # Padding phải khớp với lúc ký (PSS)
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256() # Hash phải khớp với lúc ký (SHA256)
            )
            log_verify("-> Chữ ký trên dữ liệu: HỢP LỆ")
            log_verify("--- Xác thực Thành công ---")
            return True, "\n".join(log_messages_verify) + "\n" + "Chữ ký hợp lệ và được tin cậy"
        except Exception as e:
            msg = f"!!! LỖI: Chữ ký trên dữ liệu KHÔNG HỢP LỆ. Dữ liệu có thể đã bị thay đổi hoặc chữ ký không đúng. {e}"
            log_verify(msg)
            return False, "\n".join(log_messages_verify) + "\n" + "Chữ ký không khớp với dữ liệu"

    except Exception as e: # Bắt lỗi chung ở ngoài cùng
        msg = f"!!! LỖI không xác định trong quá trình xác thực: {e}"
        log_verify(msg)
        return False, "\n".join(log_messages_verify) + "\n" + f"Lỗi không xác định: {e}"

# END COPY BACKEND FUNCTIONS


# --- Lớp Giao diện Ứng dụng ---
class SignatureApp:
    def __init__(self, master):
        self.master = master
        master.title("Công cụ Ký và Xác thực Chữ ký số Demo")
        master.geometry("800x750") # Tăng chiều cao cửa sổ

        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam') # Chọn theme (có thể thử 'alt', 'default', 'classic')

        # --- Variables ---
        self.ca_key_file = tk.StringVar(value="ca_private_key.pem")
        self.ca_cert_file = tk.StringVar(value="ca_certificate.pem")
        self.user_key_file = tk.StringVar(value="user_private_key.pem")
        self.user_cert_file = tk.StringVar(value="user_certificate.pem")
        self.password = tk.StringVar(value="your-secure-password")
        self.data_to_sign_var = tk.StringVar()
        self.signature_var = tk.StringVar()
        self.data_to_verify_var = tk.StringVar()
        self.signature_to_verify_var = tk.StringVar()

        # --- Layout ---
        main_frame = ttk.Frame(master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Configuration Frame ---
        config_frame = ttk.LabelFrame(main_frame, text="Cấu hình File", padding="10")
        config_frame.pack(fill=tk.X, pady=5)
        self._create_config_widgets(config_frame)

        # --- Actions Frame ---
        actions_frame = ttk.Frame(main_frame, padding="10")
        actions_frame.pack(fill=tk.X, pady=5)

        # --- Generation Frame ---
        gen_frame = ttk.LabelFrame(actions_frame, text="Tạo Key/Certificate (Demo)", padding="10")
        gen_frame.pack(side=tk.LEFT, padx=5, fill=tk.Y)
        self._create_generation_widgets(gen_frame)

        # --- Signing Frame ---
        sign_frame = ttk.LabelFrame(actions_frame, text="Ký Dữ liệu", padding="10")
        sign_frame.pack(side=tk.LEFT, padx=5, fill=tk.Y, expand=True)
        self._create_signing_widgets(sign_frame)

        # --- Verification Frame ---
        verify_frame = ttk.LabelFrame(actions_frame, text="Xác thực Chữ ký", padding="10")
        verify_frame.pack(side=tk.LEFT, padx=5, fill=tk.Y, expand=True)
        self._create_verification_widgets(verify_frame)

        # --- Log Frame ---
        log_frame = ttk.LabelFrame(main_frame, text="Log Messages", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=70, height=15)
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log_area.configure(state='disabled') # Read-only

    def _create_config_widgets(self, parent):
        ttk.Label(parent, text="Mật khẩu khóa bí mật:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        ttk.Entry(parent, textvariable=self.password, show="*").grid(row=0, column=1, padx=5, pady=2, sticky=tk.EW)

        row_num = 1
        widget_refs = {} # Dictionary để lưu trữ tham chiếu widget nếu cần
        for label_text, var, file_type in [
            ("File khóa CA:", self.ca_key_file, "key"),
            ("File cert CA:", self.ca_cert_file, "cert"),
            ("File khóa User:", self.user_key_file, "key"),
            ("File cert User:", self.user_cert_file, "cert"),
        ]:
            ttk.Label(parent, text=label_text).grid(row=row_num, column=0, padx=5, pady=2, sticky=tk.W)
            entry = ttk.Entry(parent, textvariable=var, width=40)
            entry.grid(row=row_num, column=1, padx=5, pady=2, sticky=tk.EW)
            browse_button = ttk.Button(parent, text="Browse...", command=lambda v=var, ft=file_type: self.browse_file(v, ft))
            browse_button.grid(row=row_num, column=2, padx=5, pady=2)
            # --- THÊM NÚT XEM CHI TIẾT ---
            if file_type == "cert":
                view_button = ttk.Button(parent, text="Xem C.Tiết",
                                         command=lambda v=var: self.display_certificate_info(v.get())) # Truyền đường dẫn file
                view_button.grid(row=row_num, column=3, padx=5, pady=2)
            # ------------------------------
            widget_refs[label_text] = {'label': ttk.Label, 'entry': entry, 'browse': browse_button}
            row_num += 1

        parent.columnconfigure(1, weight=1) # Cho phép entry mở rộng

    # --- Hàm mới để định dạng chi tiết Cert ---
    def format_certificate_details(self, cert):
        """Định dạng thông tin chi tiết của đối tượng Certificate."""
        details = []

        details.append("--- Thông tin Chứng thư ---")

        # 1. Subject (Chủ thể)
        details.append("Chủ thể (Subject):")
        for attr in cert.subject:
            details.append(f"  - {attr.oid._name}: {attr.value}") # Sử dụng tên gợi nhớ của OID

        # 2. Issuer (Người cấp)
        details.append("Người cấp (Issuer):")
        for attr in cert.issuer:
            details.append(f"  - {attr.oid._name}: {attr.value}")

        # 3. Validity Period (Thời hạn hiệu lực) - Hiển thị UTC
        details.append("Thời hạn hiệu lực:")
        details.append(f"  - Từ (Not Before UTC): {cert.not_valid_before_utc}")
        details.append(f"  - Đến (Not After UTC):  {cert.not_valid_after_utc}")

        # 4. Serial Number
        details.append(f"Số Serial: {cert.serial_number}")

        # 5. Public Key Info (Thông tin Khóa Công khai)
        public_key = cert.public_key()
        key_info = f"Khóa Công khai: Loại = "
        key_size = "N/A"
        if isinstance(public_key, rsa.RSAPublicKey):
            key_info += "RSA"
            key_size = f"{public_key.key_size} bits"
        # Thêm các loại khóa khác nếu cần (ECC, DSA...)
        # elif isinstance(public_key, ec.EllipticCurvePublicKey):
        #    key_info += f"ECC ({public_key.curve.name})"
        #    key_size = f"{public_key.key_size} bits"
        else:
             key_info += type(public_key).__name__

        key_info += f", Kích thước = {key_size}"
        details.append(key_info)

        # 6. Signature Algorithm (Thuật toán chữ ký của CA trên Cert này)
        try:
            sig_alg_name = cert.signature_algorithm_oid._name
        except AttributeError:
            sig_alg_name = str(cert.signature_algorithm_oid) # Fallback nếu không có tên gợi nhớ
        details.append(f"Thuật toán Chữ ký Chứng thư: {sig_alg_name}")

        # 7. Extensions (Phần mở rộng) - Hiển thị một số cái thông dụng
        details.append("Phần mở rộng (Extensions):")
        try:
            for ext in cert.extensions:
                ext_val = ext.value
                ext_name = ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid)
                ext_critical = "Yes" if ext.critical else "No"
                ext_details = f"  - {ext_name} (Critical: {ext_critical}): "

                if isinstance(ext_val, x509.BasicConstraints):
                    ext_details += f"Is CA = {ext_val.ca}"
                    if ext_val.path_length is not None:
                        ext_details += f", Path Length = {ext_val.path_length}"
                elif isinstance(ext_val, x509.KeyUsage):
                     usages = []
                     if ext_val.digital_signature: usages.append("Digital Signature")
                     if ext_val.content_commitment: usages.append("Content Commitment")
                     if ext_val.key_encipherment: usages.append("Key Encipherment")
                     if ext_val.data_encipherment: usages.append("Data Encipherment")
                     if ext_val.key_agreement: usages.append("Key Agreement")
                     if ext_val.key_cert_sign: usages.append("Key Cert Sign")
                     if ext_val.crl_sign: usages.append("CRL Sign")
                     ext_details += ", ".join(usages) if usages else "None"
                elif isinstance(ext_val, x509.ExtendedKeyUsage):
                    usages = [oid._name for oid in ext_val]
                    ext_details += ", ".join(usages) if usages else "None"
                elif isinstance(ext_val, x509.SubjectAlternativeName):
                    # Hiển thị các loại tên phổ biến
                    names = []
                    for general_name in ext_val:
                        if isinstance(general_name, x509.DNSName):
                            names.append(f"DNS:{general_name.value}")
                        elif isinstance(general_name, x509.IPAddress):
                             names.append(f"IP:{general_name.value}")
                        elif isinstance(general_name, x509.DirectoryName):
                             names.append(f"DirName:{general_name.value}") # value is an x509.Name
                        elif isinstance(general_name, x509.RFC822Name): # Email
                             names.append(f"Email:{general_name.value}")
                        else:
                             names.append(str(general_name))
                    ext_details += ", ".join(names) if names else "None"
                elif isinstance(ext_val, x509.CRLDistributionPoints):
                     points = [str(dp.full_name) for dp in ext_val if dp.full_name]
                     ext_details += ", ".join(points) if points else "N/A"
                elif isinstance(ext_val, x509.AuthorityInformationAccess):
                     descs = [f"{desc.access_method._name}: {desc.access_location.value}" for desc in ext_val]
                     ext_details += "; ".join(descs) if descs else "N/A"

                # Chỉ thêm vào danh sách nếu có thông tin hữu ích được trích xuất
                # (Tránh hiển thị các extension phức tạp mà không phân tích được)
                if len(ext_details) > len(f"  - {ext_name} (Critical: {ext_critical}): "):
                     details.append(ext_details)

        except x509.ExtensionNotFound:
            details.append("  (Không tìm thấy extension hoặc có lỗi khi đọc)")
        except Exception as e:
             details.append(f"  (Lỗi khi đọc extension: {e})")


        details.append("--------------------------")
        return "\n".join(details)

    # --- Hàm mới để xử lý sự kiện nút "Xem Chi tiết" ---
    def display_certificate_info(self, cert_filepath):
        """Tải và hiển thị thông tin chi tiết của file chứng thư được chọn."""
        if not cert_filepath:
            messagebox.showwarning("Chưa chọn file", "Vui lòng nhập hoặc chọn đường dẫn file chứng thư.")
            return

        if not os.path.exists(cert_filepath):
             messagebox.showerror("Lỗi", f"File chứng thư không tồn tại:\n{cert_filepath}")
             self.log_message(f"Lỗi: Không tìm thấy file {cert_filepath}")
             return

        self.log_message(f"\nĐang đọc chi tiết chứng thư từ: {cert_filepath}...")
        try:
            cert = load_certificate(cert_filepath)
            if cert:
                formatted_details = self.format_certificate_details(cert)
                self.log_message(formatted_details)
            else:
                # Lỗi đã được log bên trong load_certificate nếu có
                 messagebox.showerror("Lỗi", f"Không thể tải chứng thư từ:\n{cert_filepath}")
        except Exception as e:
            messagebox.showerror("Lỗi đọc Chứng thư", f"Đã xảy ra lỗi khi đọc file chứng thư:\n{e}")
            self.log_message(f"Lỗi nghiêm trọng khi đọc {cert_filepath}: {e}")

    def _create_generation_widgets(self, parent):
        ttk.Button(parent, text="Tạo CA Key/Cert\n(Nếu chưa có)", command=self.generate_ca).pack(pady=5, fill=tk.X)
        ttk.Button(parent, text="Tạo User Key\n(Nếu chưa có)", command=self.generate_user_key).pack(pady=5, fill=tk.X)
        ttk.Button(parent, text="Tạo User CSR/Cert\n(Nếu chưa có)", command=self.generate_user_cert).pack(pady=5, fill=tk.X)

    def _create_signing_widgets(self, parent):
        ttk.Label(parent, text="Dữ liệu cần ký:").pack(anchor=tk.W)
        data_sign_entry = ttk.Entry(parent, textvariable=self.data_to_sign_var, width=40)
        data_sign_entry.pack(fill=tk.X, pady=2)
        ttk.Button(parent, text="Load Data từ File...", command=self.load_data_to_sign).pack(pady=2, anchor=tk.W)

        ttk.Button(parent, text="Ký Dữ liệu", command=self.perform_sign).pack(pady=10)

        ttk.Label(parent, text="Chữ ký (Hex):").pack(anchor=tk.W)
        sign_result_entry = ttk.Entry(parent, textvariable=self.signature_var, state='readonly', width=40)
        sign_result_entry.pack(fill=tk.X, pady=2)
        ttk.Button(parent, text="Save Chữ ký vào File...", command=self.save_signature).pack(pady=2, anchor=tk.W)

    def _create_verification_widgets(self, parent):
        ttk.Label(parent, text="Dữ liệu cần xác thực:").pack(anchor=tk.W)
        data_verify_entry = ttk.Entry(parent, textvariable=self.data_to_verify_var, width=40)
        data_verify_entry.pack(fill=tk.X, pady=2)
        ttk.Button(parent, text="Load Data từ File...", command=self.load_data_to_verify).pack(pady=2, anchor=tk.W)

        ttk.Label(parent, text="Chữ ký cần xác thực (Hex):").pack(anchor=tk.W)
        sig_verify_entry = ttk.Entry(parent, textvariable=self.signature_to_verify_var, width=40)
        sig_verify_entry.pack(fill=tk.X, pady=2)
        ttk.Button(parent, text="Load Chữ ký từ File...", command=self.load_signature_to_verify).pack(pady=2, anchor=tk.W)

        ttk.Button(parent, text="Xác thực Chữ ký", command=self.perform_verify).pack(pady=10)

        self.verify_status_label = ttk.Label(parent, text="Kết quả: [Chưa xác thực]", foreground="blue")
        self.verify_status_label.pack(pady=5)

    # --- Logging ---
    def log_message(self, message):
        self.log_area.configure(state='normal') # Enable writing
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.configure(state='disabled') # Disable writing
        self.log_area.see(tk.END) # Scroll to the end
        self.master.update_idletasks() # Update UI immediately

    # --- File Dialogs ---
    def browse_file(self, var, file_type):
        if file_type == "key":
            filename = filedialog.askopenfilename(
                title="Chọn file khóa (.pem)",
                filetypes=(("PEM files", "*.pem"), ("All files", "*.*"))
            )
        elif file_type == "cert":
             filename = filedialog.askopenfilename(
                title="Chọn file chứng thư (.pem, .crt)",
                filetypes=(("PEM/CRT files", "*.pem *.crt"), ("All files", "*.*"))
            )
        else: # Generic save/open
             filename = filedialog.askopenfilename(title="Chọn file")

        if filename:
            var.set(filename)

    def load_data_to_sign(self):
        filename = filedialog.askopenfilename(title="Chọn file dữ liệu để ký")
        if filename:
            try:
                with open(filename, "rb") as f:
                    data = f.read()
                # Hiển thị vài byte đầu hoặc thông báo thành công
                # Đối với UI, không nên load toàn bộ file lớn vào Entry
                self.data_to_sign_var.set(f"<Dữ liệu từ file: {os.path.basename(filename)}>")
                self._loaded_data_to_sign = data # Lưu dữ liệu thực tế vào biến tạm
                self.log_message(f"Đã tải dữ liệu để ký từ: {filename}")
            except Exception as e:
                messagebox.showerror("Lỗi đọc file", f"Không thể đọc file dữ liệu: {e}")
                self.log_message(f"Lỗi đọc file dữ liệu: {e}")
                self._loaded_data_to_sign = None

    def load_data_to_verify(self):
        filename = filedialog.askopenfilename(title="Chọn file dữ liệu để xác thực")
        if filename:
            try:
                with open(filename, "rb") as f:
                    data = f.read()
                self.data_to_verify_var.set(f"<Dữ liệu từ file: {os.path.basename(filename)}>")
                self._loaded_data_to_verify = data
                self.log_message(f"Đã tải dữ liệu để xác thực từ: {filename}")
            except Exception as e:
                messagebox.showerror("Lỗi đọc file", f"Không thể đọc file dữ liệu: {e}")
                self.log_message(f"Lỗi đọc file dữ liệu: {e}")
                self._loaded_data_to_verify = None

    def save_signature(self):
        signature_hex = self.signature_var.get()
        if not signature_hex:
            messagebox.showwarning("Chưa có chữ ký", "Vui lòng tạo chữ ký trước khi lưu.")
            return
        filename = filedialog.asksaveasfilename(
            title="Lưu file chữ ký",
            defaultextension=".sig",
            filetypes=(("Signature files", "*.sig"), ("Binary files", "*.bin"),("All files", "*.*"))
            )
        if filename:
            try:
                signature_bytes = bytes.fromhex(signature_hex)
                with open(filename, "wb") as f:
                    f.write(signature_bytes)
                self.log_message(f"Đã lưu chữ ký vào: {filename}")
            except Exception as e:
                messagebox.showerror("Lỗi lưu file", f"Không thể lưu file chữ ký: {e}")
                self.log_message(f"Lỗi lưu file chữ ký: {e}")

    def load_signature_to_verify(self):
        filename = filedialog.askopenfilename(
            title="Chọn file chữ ký",
            filetypes=(("Signature files", "*.sig"), ("Binary files", "*.bin"),("All files", "*.*"))
            )
        if filename:
             try:
                with open(filename, "rb") as f:
                    signature_bytes = f.read()
                self.signature_to_verify_var.set(signature_bytes.hex())
                self.log_message(f"Đã tải chữ ký để xác thực từ: {filename}")
             except Exception as e:
                messagebox.showerror("Lỗi đọc file", f"Không thể đọc file chữ ký: {e}")
                self.log_message(f"Lỗi đọc file chữ ký: {e}")


    # --- Action Handlers ---
    def generate_ca(self):
        self.log_message("Bắt đầu tạo CA key/cert...")
        ca_key_f = self.ca_key_file.get()
        ca_cert_f = self.ca_cert_file.get()
        pwd = self.password.get()

        if os.path.exists(ca_key_f) or os.path.exists(ca_cert_f):
             if not messagebox.askyesno("Xác nhận ghi đè", f"File {ca_key_f} hoặc {ca_cert_f} đã tồn tại. Bạn có muốn ghi đè?"):
                 self.log_message("Hủy tạo CA key/cert.")
                 return

        try:
            # Thông tin CA (có thể thêm input fields trên UI để tùy chỉnh)
            country = "VN"
            state = "Ho Chi Minh"
            locality = "Ho Chi Minh City"
            org_name = "My Demo CA Ltd UI"
            common_name = "My Demo Root CA UI"

            ca_key = generate_private_key(ca_key_f, pwd)
            self.log_message(f"Đã tạo CA key: {ca_key_f}")
            create_self_signed_ca_cert(
                ca_key, ca_cert_f, country, state, locality, org_name, common_name
            )
            self.log_message(f"Đã tạo CA cert: {ca_cert_f}")
            messagebox.showinfo("Hoàn thành", "Tạo CA Key và Certificate thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi tạo CA", f"Đã xảy ra lỗi: {e}")
            self.log_message(f"Lỗi khi tạo CA: {e}")

    def generate_user_key(self):
        self.log_message("Bắt đầu tạo User key...")
        user_key_f = self.user_key_file.get()
        pwd = self.password.get()

        if os.path.exists(user_key_f):
             if not messagebox.askyesno("Xác nhận ghi đè", f"File {user_key_f} đã tồn tại. Bạn có muốn ghi đè?"):
                 self.log_message("Hủy tạo User key.")
                 return

        try:
            generate_private_key(user_key_f, pwd)
            self.log_message(f"Đã tạo User key: {user_key_f}")
            messagebox.showinfo("Hoàn thành", "Tạo User Key thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi tạo User Key", f"Đã xảy ra lỗi: {e}")
            self.log_message(f"Lỗi khi tạo User Key: {e}")

    def generate_user_cert(self):
        self.log_message("Bắt đầu tạo User CSR/Cert...")
        user_key_f = self.user_key_file.get()
        user_cert_f = self.user_cert_file.get()
        ca_key_f = self.ca_key_file.get()
        ca_cert_f = self.ca_cert_file.get()
        pwd = self.password.get()

        if not os.path.exists(user_key_f):
            messagebox.showerror("Thiếu file", f"Không tìm thấy file User key: {user_key_f}. Vui lòng tạo trước.")
            self.log_message(f"Lỗi: Thiếu User Key {user_key_f}")
            return
        if not os.path.exists(ca_key_f) or not os.path.exists(ca_cert_f):
             messagebox.showerror("Thiếu file", f"Không tìm thấy file CA key hoặc cert. Vui lòng tạo trước.")
             self.log_message(f"Lỗi: Thiếu CA Key/Cert")
             return

        if os.path.exists(user_cert_f):
             if not messagebox.askyesno("Xác nhận ghi đè", f"File {user_cert_f} đã tồn tại. Bạn có muốn ghi đè?"):
                 self.log_message("Hủy tạo User cert.")
                 return

        try:
             # Thông tin User (có thể thêm input fields trên UI để tùy chỉnh)
            country = "VN"
            state = "Ho Chi Minh"
            locality = "Thu Duc"
            org_name = "My Test Company UI"
            common_name = "Bob Test User UI" # Đổi tên để khác demo trước

            user_key = load_private_key(user_key_f, pwd)
            ca_key = load_private_key(ca_key_f, pwd)
            ca_cert = load_certificate(ca_cert_f)

            user_csr = create_csr(user_key, country, state, locality, org_name, common_name)
            self.log_message("Đã tạo User CSR.")
            sign_csr(user_csr, ca_key, ca_cert, user_cert_f)
            self.log_message(f"Đã tạo và ký User cert: {user_cert_f}")
            messagebox.showinfo("Hoàn thành", "Tạo User Certificate thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi tạo User Cert", f"Đã xảy ra lỗi: {e}")
            self.log_message(f"Lỗi khi tạo User Cert: {e}")

    def perform_sign(self):
        self.log_message("Bắt đầu ký dữ liệu...")
        user_key_f = self.user_key_file.get()
        pwd = self.password.get()
        data_str = self.data_to_sign_var.get()

        # Kiểm tra xem dữ liệu được nhập trực tiếp hay tải từ file
        if hasattr(self, '_loaded_data_to_sign') and self._loaded_data_to_sign is not None:
            data_bytes = self._loaded_data_to_sign
            self.log_message("Sử dụng dữ liệu đã tải từ file để ký.")
            # Xóa dữ liệu tạm sau khi dùng để tránh dùng nhầm lần sau
            self._loaded_data_to_sign = None
            # Cập nhật lại text box để rõ ràng
            # self.data_to_sign_var.set(f"<Đã sử dụng dữ liệu từ file>")
        elif data_str and not data_str.startswith("<Dữ liệu từ file:"):
             data_bytes = data_str.encode('utf-8') # Giả sử dữ liệu nhập là text UTF-8
             self.log_message("Sử dụng dữ liệu nhập từ text box để ký.")
        else:
             messagebox.showerror("Thiếu dữ liệu", "Vui lòng nhập dữ liệu hoặc tải dữ liệu từ file để ký.")
             self.log_message("Lỗi: Không có dữ liệu để ký.")
             return

        if not os.path.exists(user_key_f):
             messagebox.showerror("Thiếu file", f"Không tìm thấy file User key: {user_key_f}")
             self.log_message(f"Lỗi: Thiếu User Key {user_key_f}")
             return

        try:
            signature = sign_data(data_bytes, user_key_f, pwd)
            sig_hex = signature.hex()
            self.signature_var.set(sig_hex)
            self.log_message(f"Ký dữ liệu thành công. Chữ ký (Hex): {sig_hex[:30]}...") # Hiển thị một phần
            messagebox.showinfo("Hoàn thành", "Ký dữ liệu thành công!")
        except Exception as e:
            messagebox.showerror("Lỗi Ký", f"Đã xảy ra lỗi khi ký: {e}")
            self.log_message(f"Lỗi khi ký dữ liệu: {e}")
            self.signature_var.set("") # Xóa chữ ký cũ nếu lỗi

    def perform_verify(self):
        self.log_message("Bắt đầu xác thực chữ ký...")
        self.verify_status_label.config(text="Kết quả: [Đang xác thực...]", foreground="orange")

        signer_cert_f = self.user_cert_file.get() # Giả định user cert là của người ký
        ca_cert_f = self.ca_cert_file.get()
        signature_hex = self.signature_to_verify_var.get()
        data_str = self.data_to_verify_var.get()

        # Kiểm tra xem dữ liệu được nhập trực tiếp hay tải từ file
        if hasattr(self, '_loaded_data_to_verify') and self._loaded_data_to_verify is not None:
            data_bytes = self._loaded_data_to_verify
            self.log_message("Sử dụng dữ liệu đã tải từ file để xác thực.")
            self._loaded_data_to_verify = None
            # self.data_to_verify_var.set(f"<Đã sử dụng dữ liệu từ file>")
        elif data_str and not data_str.startswith("<Dữ liệu từ file:"):
             data_bytes = data_str.encode('utf-8') # Giả sử dữ liệu nhập là text UTF-8
             self.log_message("Sử dụng dữ liệu nhập từ text box để xác thực.")
        else:
             messagebox.showerror("Thiếu dữ liệu", "Vui lòng nhập dữ liệu hoặc tải dữ liệu từ file để xác thực.")
             self.log_message("Lỗi: Không có dữ liệu để xác thực.")
             self.verify_status_label.config(text="Kết quả: [Lỗi thiếu dữ liệu]", foreground="red")
             return

        if not signature_hex:
            messagebox.showerror("Thiếu chữ ký", "Vui lòng nhập chữ ký (Hex) hoặc tải chữ ký từ file.")
            self.log_message("Lỗi: Thiếu chữ ký để xác thực.")
            self.verify_status_label.config(text="Kết quả: [Lỗi thiếu chữ ký]", foreground="red")
            return

        if not os.path.exists(signer_cert_f) or not os.path.exists(ca_cert_f):
             messagebox.showerror("Thiếu file", f"Không tìm thấy file chứng thư người ký hoặc CA.")
             self.log_message(f"Lỗi: Thiếu file cert {signer_cert_f} hoặc {ca_cert_f}")
             self.verify_status_label.config(text="Kết quả: [Lỗi thiếu file cert]", foreground="red")
             return

        try:
            signature_bytes = bytes.fromhex(signature_hex)
        except ValueError:
             messagebox.showerror("Lỗi định dạng", "Chuỗi chữ ký không phải là định dạng Hex hợp lệ.")
             self.log_message("Lỗi: Chữ ký không đúng định dạng Hex.")
             self.verify_status_label.config(text="Kết quả: [Lỗi định dạng chữ ký]", foreground="red")
             return

        # Gọi hàm verify gốc và lấy kết quả + log chi tiết
        is_valid, detailed_message = verify_signature(data_bytes, signature_bytes, signer_cert_f, ca_cert_f)

        # Hiển thị log chi tiết từ hàm verify
        self.log_message(detailed_message)

        # Cập nhật label trạng thái cuối cùng
        if is_valid:
            self.verify_status_label.config(text="Kết quả: HỢP LỆ", foreground="green")
            messagebox.showinfo("Hoàn thành", "Xác thực thành công! Chữ ký hợp lệ.")
        else:
            self.verify_status_label.config(text="Kết quả: KHÔNG HỢP LỆ", foreground="red")
            # Lấy dòng cuối cùng của message để hiển thị tóm tắt lỗi
            last_error_line = detailed_message.strip().split('\n')[-1]
            if "!!!" in last_error_line:
                 last_error_line = last_error_line.split("!!!")[1].strip()

            messagebox.showerror("Thất bại", f"Xác thực thất bại! Lý do: {last_error_line}")


# --- Khởi chạy ứng dụng ---
if __name__ == "__main__":
    root = tk.Tk()
    app = SignatureApp(root)
    root.mainloop()