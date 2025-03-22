# Digital-Signature
Mở terminal chạy dòng này để cài thư viện: pip install pycryptodome 

key.py: tạo khóa
sign.py: ký số
check.py: kiểm tra chữ ký

Thứ tự chạy file:
key -> sign -> check

Khi tạo khóa sẽ tạo ra khóa công khai và khóa bí mật được lưu vào 2 file public.key và private.key

Tạo 1 thông điệp mẫu -> Tạo hàm băm cho thông điệp -> Dùng private key để ký số -> Lưu chữ ký và thông điệp vào file signature.pem và message.txt

Để kiểm tra: Đọc public key từ file public.key -> Đọc thông điệp từ file message.txt -> Đọc chữ ký từ file signature.pem -> Tạo băm của thông điệp -> Dùng public key giải mã chữ ký thu được hàm băm -> So sánh 2 hàm băm (Giống -> Thật, Khác -> Giả) (Ở đây không cần viết hàm giải mã chữ ký bởi vì thư viện Crypto.Signature.pkcs1_15 đã thực hiện việc đó trong hàm .verify()
