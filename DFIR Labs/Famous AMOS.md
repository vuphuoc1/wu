Description
Cortex XDR has been flagging alerts non-stop this Friday due to a suspicious file being downloaded by Zhu Yuan. Thankfully, my Wireshark was running so we managed to track down some of the malicious activity. It seems like the user received a malicious attachment from an unknown domain via email, and executed it in their machine.

Chall cho mình 1 file pcap, mở bằng wireshark

Kiểm tra bảng Protocol Hierarchy Statistics trong Wireshark, chúng ta phát hiện một lượng nhỏ dữ liệu truyền qua giao thức HTTP nhưng chứa các payload có kích thước bất thường (MIME Multipart và PNG).

<img width="1683" height="637" alt="image" src="https://github.com/user-attachments/assets/d993c74c-e6c6-4ebd-ac1d-dbf462711224" />


Lọc các HTTP request và sử dụng tính năng File > Export Objects > HTTP, chúng ta thu được các file đáng ngờ đang giao tiếp với một máy chủ C2 qua Ngrok (b2eb-115-135-31-192.ngrok-free.app):

<img width="1024" height="529" alt="image" src="https://github.com/user-attachments/assets/2a549c3e-155d-4787-a5be-d789a7a0dff7" />

LegitLobsterGameDownloader.dmg 

bangboo.png (94 kB) - File ảnh tải xuống.

joinsystem - Gói dữ liệu multipart/form-data 

Ngoài ra khi check packet chứa joinsystem thì mình còn nhận ra đây là 1 file zip:

<img width="1917" height="980" alt="image" src="https://github.com/user-attachments/assets/9018e08f-0c1a-4c12-9369-b08b84672468" />

Khi unzip thì mình thu được file flag.enc và tệp hệ thống bị mã độc đánh cắp. Có vẻ như flag đã bị encrypt và chúng ta cần phải decrypt

Tiếp đến mình phân tích thử LegitLobsterGameDownloader.dmg , theo như mình tìm hiểu file dmg là 1 file đĩa ảo của apple và có thể dùng 7z để bung nó ra.


