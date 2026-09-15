Challenge Description
Randon, an IT employee finds a USB on his desk after recess. Unable to contain his curiosity he decides to plug it in. Suddenly the computer goes haywire and before he knows it, some windows pops open and closes on its own. With no clue of what just happened, he tries seeking help from a colleague. Even after Richard's effort to remove the malware, Randon noticed that the malware persisted after his system restarted.

NOTE: All timestamps are in IST.

Questions
you can either directly answer it or you can solve the challenge by running main.py in Solution folder and answering it.
```
Q1) What is the serial number of the sandisk usb that he plugged into the system? And when did he plug it into the system?
Format: verboten{serial_number:YYYY-MM-DD-HH-MM-SS}

Q2) What is the hash of the url from which the executable in the usb downloaded the malware from?
Format: verboten{md5(url)}

Q3) What is the hash of the malware that the executable in the usb downloaded which persisted even after the efforts to remove the malware?
Format: verboten{md5{malware_executable)}

Q4) What is the hash of the zip file and the invite address of the remote desktop that was sent through slack?
Format: verboten{md5(zip_file):invite_address}

Q5) What is the hash of all the files that were synced to Google Drive before it was shredded?
Format: verboten{md5 of each file separated by ':'}

Q6) What is time of the incoming connection on AnyDesk? And what is the ID of user from which the connection is requested?
Format: verboten{YYYY-MM-DD-HH-MM-SS:user_id}

Q7) When was the shredder executed?
Format: verboten{YYYY-MM-DD-HH-MM-SS}

Q8) What are the answers of the backup questions for resetting the windows password?
Format: verboten{answer_1:answer_2:answer_3}

Q9) What is the single use code that he copied into the clipboard and when did he copy it?
Format: verboten{single_use_code:YYYY-MM-DD-HH-MM-SS}
```

Q1) What is the serial number of the sandisk usb that he plugged into the system? And when did he plug it into the system?
Format: verboten{serial_number:YYYY-MM-DD-HH-MM-SS} : verboten{4C530001090312109353&0:2024-02-16 12:01:57

Load key SYSTEM trong path sau : c:windows/system32/config


<img width="1900" height="1005" alt="image" src="https://github.com/user-attachments/assets/f629d246-fbe1-4fe2-8791-6782e2924b85" />


Q2) What is the hash of the url from which the executable in the usb downloaded the malware from?
Format: verboten{md5(url)}

Thực chất, chiếc USB độc hại (BadUSB) đã chạy một tập lệnh tự động mở trình duyệt web của nạn nhân để kéo file mã độc xuống. Do đó, manh mối chính xác nhất cho câu này nằm ẩn bên trong Lịch sử duyệt web (Browser History).

điều hướng đến thư mục profile Chrome của user randon:
[root]\Users\randon\AppData\Local\Google\Chrome\User Data\Default\

<img width="1914" height="671" alt="image" src="https://github.com/user-attachments/assets/45ad970e-769b-4874-bb16-c017bc1f0484" />

Có thể thấy format của file history là sql3 nên dùng db browser để mở

Tiến hành xem bảng các bảng liên quan đến url và mình tìm được 1 url độc hại:

<img width="1919" height="345" alt="image" src="https://github.com/user-attachments/assets/3baf8d82-7749-454a-9a7a-423ab3e9b485" />

https://filebin.net/qde72esvln1cor0t/mal

Và từ cả target path ta có thể thấy tệp đã được tải xuống tại path này:

<img width="1919" height="520" alt="image" src="https://github.com/user-attachments/assets/ddaa0d45-a5cc-42e1-b122-e63a0f61311a" />


verboten{11ecc1766b893aa2835f5e185147d1d2}



Q3) What is the hash of the malware that the executable in the usb downloaded which persisted even after the efforts to remove the malware?
Format: verboten{md5{malware_executable)}

<img width="1891" height="502" alt="image" src="https://github.com/user-attachments/assets/f231932b-8c25-43ed-92d3-f1faa13a4839" />

Có vẻ như malware này chỉ đóng vai trò dropper/downloader và nó tải về 1 payload độc hại là Agent Tesla và đề bài yêu cầu mã md5 này

verboten{7b42afaa8d13acf084d3784cbc0bd4c2}



Q4) What is the hash of the zip fle and the iinvite address of the remote desktop that was sent through slack?

Ứng dụng Slack lưu trữ lịch sử tin nhắn cục bộ (local cache) dưới dạng cơ sở dữ liệu LevelDB nên mình sẽ mò vào path [root]\Users\randon\AppData\Roaming\Slack\IndexedDB\

<img width="1641" height="842" alt="image" src="https://github.com/user-attachments/assets/85b786de-4ce0-4db6-867c-58a4b0bcbd96" />


Mình thấy 1 file a nằm trong thư mục blob. Có vẻ file này chính là một file cơ sở dữ liệu lưu lại bộ nhớ đệm các đoạn chat của Slack bởi vì có thể thấy các từ khóa JSON hiển thị ở cột Text bên phải như invite_links, reactions, mentions...). và mục đích của chúng ta gồm tìm tin nhắn chứa AnyDesk ID và tên file ZIP
Ctrl +f lọc từ khóa anydesk mình thu được id:1541069606

<img width="1021" height="267" alt="image" src="https://github.com/user-attachments/assets/56bfd4f1-a922-4054-9586-30dc3d44f202" />

ctrl+f lọc .zip mình tìm được tên file zip : file_shredders.zip

<img width="1479" height="469" alt="image" src="https://github.com/user-attachments/assets/846efd9b-8ea4-4c03-ab3f-33a87b4285d3" />

Và để trích xuất được file zip thì mình vào bộ nhớ cache để tìm

<img width="1836" height="913" alt="image" src="https://github.com/user-attachments/assets/885ff914-c69d-4c86-a0a5-4d0b69d9bfa6" />

Mình tìm thấy 1 file có header là PK định dạng đặc trưng của file zip nên chắc đây là file mình cần tìm, trích ra rồi tìm md5 là xong


verboten{b092eb225b07e17ba8a70b755ba97050:1541069606}

Q5) What is the hash of all the files that were synced to Google Drive before it was shredded?

Quay lại FTK mình trỏ vào DriveFS thì và vào content cache thì mình tìm thấy 5 thư mục con

<img width="1537" height="691" alt="image" src="https://github.com/user-attachments/assets/ab199e00-3e61-4843-910d-8da6391d931b" />


3 trong số 5 file thì header đặc trưng của file zip , hash 3 file đó mình có câu trả lời:

verboten{ae679ca994f131ea139d42b507ecf457:4a47ee64b8d91be37a279aa370753ec9:870643eec523b3f33f6f4b4758b3d14c:c143b7a7b67d488c9f9945d98c934ac6:e6e6a0a39a4b298c2034fde4b3df302a}

Q6) What is time of the incoming connection on AnyDesk? And what is the ID of user from which the connection is requested?

<img width="1917" height="515" alt="image" src="https://github.com/user-attachments/assets/5fafda25-0022-4911-9332-a145552b08d1" />


mình trỏ vào mục program data thì check được connection_trace , để kiểm tra lại có phải là kết nối của anydesk không thì mình vào roaming/anydesk để check lại 1 lần nữa , check trong file ad.trace thu được kết quả như sau:

<img width="1906" height="630" alt="image" src="https://github.com/user-attachments/assets/18b1a768-13f0-404a-a1f2-b7ca462e038f" />

Có vẻ như đúng rồi, verboten{2024-02-16-20-29-04:221436813}

Q7) When was the shredder executed?

Câu hỏi này liên quan tới việc hủy tài liệu và phần có từ "executed" , mình nghĩ attacker đã chạy 1 chương trình gì đó để xóa tài liệu , việc kiểm tra 1 chương trình đã chạy lúc nào thì chúng ta chỉ cần trỏ vào thư mục prefecth của windows.

<img width="1912" height="630" alt="image" src="https://github.com/user-attachments/assets/6e1501e2-f62a-4d00-999a-9b6c7a2eab2e" />

Sau khi tìm kiếm các chương trình xóa tài liệu trên mạng, mình thấy trong prefecth chỉ có duy nhất ứng dụng này là để tiêu hủy tài liệu, lấy date modified là ok.

 verboten{2024-02-16-08-31-06}


 Q8) What are the answers of the backup questions for resetting the windows password?


Tiến hành trích file SAM và dùng registry explore và trỏ đến root/sam/domain/account/user và trích file SAM từ đây nhé [root]\Windows\System32\config

<img width="1917" height="537" alt="image" src="https://github.com/user-attachments/assets/5782dad4-2181-4add-a9e1-ca0abf5f2148" />

verboten{Stuart:FutureKidsSchool:Howard}


Q9) What is the single use code that he copied into the clipboard and when did he copy it?

Để tìm nội dung đã được copy vào khay nhớ tạm (Clipboard) cùng với thời gian thực hiện, chúng ta sẽ phân tích một artifact tuyệt vời của Windows 10/11 có tên là Connected Devices Platform

Trỏ vào path này [root]\Users\randon\AppData\Local\ConnectedDevicesPlatform để phân tích file ActivitiesCache.db và mở với DB browser sau đó xem nội dung trong bảng activity , xem nội dung của cột clip board payload:

<img width="1917" height="681" alt="image" src="https://github.com/user-attachments/assets/e257b0e0-d0b7-4c60-8fbd-c3c664af9b0f" />

Mình thấy đoạn payload này đã được mã hóa base64 tiến hành giải mã thu được mã code dùng 1 lần 

<img width="1917" height="625" alt="image" src="https://github.com/user-attachments/assets/cd3e1a92-7501-4b01-93f2-ecb93d0de768" />

Tiếp theo là tìm thời gian, xem nội dung trong cột start time:

<img width="1700" height="685" alt="image" src="https://github.com/user-attachments/assets/ddf8c270-bdd4-46cf-aede-43d248cc20c7" />

Chuỗi số 1708106083 chính là thời gian được lưu dưới dạng Unix Epoch Time (số giây trôi qua tính từ ngày 1/1/1970). Khi quy đổi dãy số này sang thời gian thực tế (theo chuẩn giờ quốc tế UTC), chúng ta có kết quả chính xác là:2024-02-16-17-54-43

Verboten{830030:2024-02-16-23-24-43}

Khi hoàn thành xong labs thì sẽ có flag. bi0sctf{w3ll_th4t_w4s_4_v3ry_34sy_chall_b9s0w7}






 






























