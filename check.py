from Crypto.Signature import pkcs1_15 
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# Nhập khóa công khai từ file 
publicKey = RSA.import_key(open('public.key').read()) 
 
# Đọc thông điệp từ file 
file_in = open("message.txt", "rb") 
message2 = file_in.read() 
file_in.close()

# Đọc chữ ký từ file 
file_in = open("signature.pem", "rb") 
signature2 = file_in.read() 
file_in.close()

# message2 = b'Cong hoa xa hoi chu nghia viet nam'

# Tạo băm của thông điệp 
h = SHA256.new(message2) 
 
# Xác thực chữ ký 
try: 
    pkcs1_15.new(publicKey).verify(h, signature2) 
    print("Chữ ký toàn vẹn không thay đổi") 
except (ValueError, TypeError): 
    print("Chữ ký không toàn vẹn") 