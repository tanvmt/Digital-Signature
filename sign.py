from Crypto.Signature import pkcs1_15 
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
 
# Đọc khóa riêng tư từ file
private_key = RSA.import_key(open('private.key').read())

# Tạo thông điệp 
message = b'Cong hoa Xa hoi Chu nghia Viet Nam'

# Tạo giá trị băm cho thông điệp 
hash = SHA256.new(message)

# Ký chữ ký điện tử 
signer = pkcs1_15.new(private_key) 
signature = signer.sign(hash) 
print("-----------------")
print(signature)
print("-----------------")

# Chuyển chữ ký thành dạng readable (hexadecimal) 
signature_hex = signature.hex() 
 
# Lưu chữ ký vào file "signature.pem" 
file_out = open("signature.pem", "wb") 
file_out.write(signature) 
file_out.close() 
 
# Lưu thông điệp vào file "message.txt" 
file_out = open("message.txt", "wb") 
file_out.write(message) 
file_out.close() 

print("Chữ ký điện tử: ", signature_hex)