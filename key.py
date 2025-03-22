from Crypto.PublicKey import RSA 
 
# Tạo ra khóa RSA 1024 bit 
key = RSA.generate(1024) 
 
# Viết khóa riêng tư vào file 
private_key = key.export_key() 
file_out = open("private.key", "wb") 
file_out.write(private_key) 
file_out.close() 
print(private_key) 
print() 
 
# Viết khóa công khai vào file 
public_key = key.publickey().export_key() 
file_out = open("public.key", "wb") 
file_out.write(public_key)   
file_out.close() 
print(public_key) 
print() 