from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

try:
    # 1. Tạo khóa trực tiếp
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    print(">>> Khóa đã được tạo")

    # 2. Thông điệp
    message = b"abcd"
    print(f">>> Thông điệp: {message!r}")

    # 3. Băm
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(message)
    digest = hasher.finalize()
    print(f">>> Digest (hex): {digest.hex()}")

    # 4. Ký (dùng PKCS1v15)
    signature = private_key.sign(
        digest,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print(f">>> Chữ ký (hex): {signature.hex()}")

    # 5. Xác minh (dùng PKCS1v15)
    print(">>> Đang thực hiện xác minh...")
    public_key.verify(
        signature,
        digest,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    # Nếu không có lỗi, xác minh thành công
    print(">>> XÁC MINH THÀNH CÔNG!")

except Exception as e:
    print(f">>> XÁC MINH THẤT BẠI: {e}")
    import traceback
    traceback.print_exc() # In chi tiết lỗi