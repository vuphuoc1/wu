Sherlock Scenario
With help from D.I. Lestrade, Holmes acquires logs from a compromised MSP connected to the city’s financial core. The MSP’s AI helpdesk bot looks to have been manipulated into leaking remote access keys - an old trick of Moriarty’s.


<img width="1156" height="373" alt="image" src="https://github.com/user-attachments/assets/0086097c-8f83-45ec-8177-f266370e817e" />

Sau khi unzip chúng ta được 3 file như ở trên 

Task 1:What was the IP address of the decommissioned machine used by the attacker to start a chat session with MSP-HELPDESK-AI?

Dùng wireshark để mở gói pcap, vì câu hỏi đầu hỏi địa chỉ IP của máy tấn công nên ta làm như sau: Statistics ➝ Conversations ➝ IPv4 

<img width="1870" height="749" alt="image" src="https://github.com/user-attachments/assets/7261720e-a978-4098-a1ad-96b2624402cb" />

Có thể thấy máy 10.0.69.45 có lượng packet gửi đi đển server chatbot nhiều nhất nên có thể khẳng định đây là IP của máy tấn công.

<img width="1529" height="248" alt="image" src="https://github.com/user-attachments/assets/0f2cb871-0c26-4689-afc0-29cd2618bd6d" />

Task2:What was the hostname of the decommissioned machine?

Câu hỏi yêu cầu tìm tên máy chủ đã ngừng hoạt động, đẻ trả lời câu hỏi này chúng ta sẽ dùng bộ lọc trên wireshark để lọc ra các packet dùng giao thức NBNS(NetBIOS Name Service)
Giao thức này được Windows dùng để phân giải tên máy tính trong mạng nội bộ, qua đó sẽ tiết lộ hostname mà chúng ta cần tìm.

<img width="1873" height="499" alt="image" src="https://github.com/user-attachments/assets/92ee1e31-a607-4096-b7a8-72e37e669f1a" />

Có thể thấy tên hostname là: WATSON-ALPHA-2

<img width="1516" height="188" alt="image" src="https://github.com/user-attachments/assets/f1a579d7-940b-49af-95f9-e6d445f292e9" />

Task 3:What was the first message the attacker sent to the AI chatbot?

Để lọc đoạn chat đầu tiên attacker gửi cho AI chúng ta sẽ lọc giao thức HTTP cùng với địa chỉ IP của attacker vì payload JSON chứa toàn bộ thông tin về ID, content,sender,timestamp
http and ip.addr == 10.0.69.45

<img width="1570" height="293" alt="image" src="https://github.com/user-attachments/assets/a26913fb-1968-4d24-add8-b802c6ed7b83" />

Chú ý vào packet này, follow http stream 

<img width="954" height="447" alt="image" src="https://github.com/user-attachments/assets/0a717035-3afe-478e-91f9-f1756f0a38cf" />
Đây có lẽ là message đầu tiên attacker gửi cho chatbot

<img width="1505" height="281" alt="image" src="https://github.com/user-attachments/assets/684c213f-68a8-4e41-8281-f174302f81b0" />

Task 4:When did the attacker's prompt injection attack make MSP-HELPDESK-AI leak remote management tool info?

Task yêu cầu chúng ta lấy thời gian ngay sau khi nó dính prompt injection , vẫn dựa vào http và ip của attacker ở stream thứ 55 mình đã thấy câu promt injection cùng với đó là thời gian.

<img width="1569" height="711" alt="image" src="https://github.com/user-attachments/assets/ab57a862-13a5-4878-8f0d-e411293464d6" />

Nhưng có vẻ là lúc này con bot vẫn khá tỉnh và chưa tiết lộ gì , mình tiếp tục theo dõi tới luồng stream sau thì phát hiện lúc này attacker đã gửi 1 lệnh promt mạnh hơn:

<img width="1541" height="525" alt="image" src="https://github.com/user-attachments/assets/927e4b0c-ae8f-47ed-a8fe-62198d071b09" />

Sau đấy là phải hồi của con bot:

<img width="1886" height="847" alt="image" src="https://github.com/user-attachments/assets/b487ff82-3e94-48bf-94c3-88bfc6df5373" />

Nhìn vào phần đoạn chat cuối có vẻ như con bot đã tiết lộ password và RMM ID cùng với đó là thời gian cụ thể: 2025-08-19 12:02:06

<img width="1517" height="274" alt="image" src="https://github.com/user-attachments/assets/5c1cfe06-b61d-45cc-868b-41c908f9cf47" />

Task5:What is the Remote management tool Device ID and password?

<img width="1522" height="252" alt="image" src="https://github.com/user-attachments/assets/386ae78c-59f7-4921-ac68-c44ccff2d9a7" />

Task6: What was the last message the attacker sent to MSP-HELPDESK-AI?

Tiếp tục theo dõi các luồng stream ta thu được tin nhắn cuối:

<img width="1314" height="453" alt="image" src="https://github.com/user-attachments/assets/4bc50b91-3dad-4ce5-ba6b-d8e1177c6225" />


<img width="1579" height="227" alt="image" src="https://github.com/user-attachments/assets/85288294-d071-49f7-ba4a-010d01e942a1" />

Task 7:When did the attacker remotely access Cogwork Central Workstation?

Vì kẻ tấn công đã sử dụng công cụ RMM là TeamViewer (dựa trên ID và mật khẩu mà AI vừa làm lộ), dấu vết truy cập từ xa sẽ được ghi lại rất rõ ràng trong các log của phần mềm này

Mở file TRIAGE_IMAGE_COGWORK-CENTRAL: và điều hướng tới thư mục sau TRIAGE_IMAGE_COGWORK-CENTRAL\C\Program Files\TeamViewer\Connections_incoming.txt"

<img width="1487" height="735" alt="image" src="https://github.com/user-attachments/assets/3d86dd66-3408-4e5b-815f-3f8dda764a79" />


Sau khi mở file txt thì ta có thể thấy có 1 tài khoản là James Moriarty đã xâm nhập lúc 09:58:25 và kết thúc phiên lúc 10:14:27.

<img width="1458" height="270" alt="image" src="https://github.com/user-attachments/assets/ce573b87-35eb-482f-9312-07dfd5d22a92" />

Task8: What was the RMM Account name used by the attacker?

<img width="1580" height="304" alt="image" src="https://github.com/user-attachments/assets/fe1bcb6f-ca54-4073-bf56-1cee296acf16" />

Task 9:What was the machine's internal IP address from which the attacker connected?

Để tìm địa chỉ IP nội bộ chúng ta sẽ tìm trong file log mà máy attacker đã đăng nhập từ xa thông qua teamviewer

<img width="1616" height="833" alt="image" src="https://github.com/user-attachments/assets/ffeb72d0-4c62-467c-9ec2-1c73fb245ced" />

Ý tưởng ban đầu của mình sẽ là tìm kiếm ngày và giờ từ lúc mà attacker bắt đầu phiên là 9:48 và ngày 20/8 nhưng khi mở file log thì mình thấy là utc +1 nên mình nghĩ thời gian sẽ phải cộng thêm 1 tiếng

<img width="1177" height="423" alt="image" src="https://github.com/user-attachments/assets/93739ea5-476e-4ff7-aa01-196965f56f63" />


Lọc ra với từ khóa punch received vì khi hai máy cố gắng kết nối trực tiếp với nhau, TeamViewer sẽ ghi lại sự kiện nhận gói tin "punch" này, qua đó để lộ trực tiếp địa chỉ IP thật của máy khách

<img width="1423" height="715" alt="image" src="https://github.com/user-attachments/assets/2e88d713-faea-4bf0-bbe9-8de2b767a0ec" />

<img width="1543" height="299" alt="image" src="https://github.com/user-attachments/assets/1b5b0fe5-398c-4904-ae8b-227209b3ac61" />


Task 10:The attacker brought some tools to the compromised workstation to achieve its objectives. Under which path were these tools staged?

Có vẻ như attacker đã cài 1 số tools của mình, và theo kinh nghiệm thì mình đoán là mã độc nên mình lọc với .exe

<img width="1480" height="763" alt="image" src="https://github.com/user-attachments/assets/84f8c5fa-35b0-44e5-9ad4-a4e55ab22f6c" />

Qua hình ảnh kẻ tấn công mang vào máy trạm, bao gồm các công cụ quen thuộc như mimikatz.exe, webbrowserpassview.zip, credhistview.zip, và JM.exe và tất cả đều trỏ về 1 path là C:\Windows\Temp\safe.

<img width="1573" height="328" alt="image" src="https://github.com/user-attachments/assets/504aaedb-8f3c-4fa8-80a6-f8e8a64e4920" />


Task 11:The attacker staged a browser credential harvesting tool on the compromised system. How long did this tool run before it was terminated? (Provide your answer in milliseconds, rounded to the nearest thousand)

Dựa vào danh sách các file được tải xuống ở bước trước, công cụ thu thập mật khẩu trình duyệt chính là webbrowserpassview.exe (được giải nén từ file webbrowserpassview.zip). Đây là một công cụ rất nổi tiếng của NirSoft chuyên dùng để trích xuất mật khẩu lưu trên trình duyệt

Ban đầu mình tìm kiếm ở windows event logs nhưng nó chỉ ra thời điểm thực hiện process chứ không cho biết tiến trình chạy trong bao lâu, sau khi research thì mình tìm trong khóa user assit của NTUSER.DAT

Và sử dụng registry explore để load hive NTUSER.DAT trước , sau đấy tìm khóa user assit qua path sau: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

<img width="1609" height="505" alt="image" src="https://github.com/user-attachments/assets/77bbbbba-aa47-446f-a729-d8b6310317d4" />

Có vẻ như webbrowserpassview.exe chạy trong 8s quy đổi sang ms là 8000

<img width="1509" height="305" alt="image" src="https://github.com/user-attachments/assets/c02e126b-e2af-424b-97e9-fe05c1bc1088" />

Task 12:The attacker executed a OS Credential dumping tool on the system. When was the tool executed?

Đến đây câu hỏi lại muốn chúng ta biết tools trích xuất mật khẩu hệ điều hành trên hệ thống mà attacker đã chạy khi nào, tools đó chính là mimikatz. Mình check trong event logs thì không tìm thấy mimikatz 

Vì không có log thực thi trực tiếp và bài lab này cũng không cung cấp sẵn thư mục Prefetch, nên mình phân tích USN Journal ($J).

<img width="1534" height="369" alt="image" src="https://github.com/user-attachments/assets/3b3b923d-f8d5-40ef-81c3-db159c84790c" />

Tìm hiểu thêm về fiel $I thì File này là một cuốn nhật ký ghi lại mọi thay đổi trên ổ đĩa (tạo, sửa, xóa file).

Sau đó mình sài tools ntfs log tracker để load file này vào và export ra 1 file csv , vì đề hỏi là " excuted" nên mình search với từ khóa là MIMIKATZ or .pf



<img width="1895" height="729" alt="image" src="https://github.com/user-attachments/assets/9d53c029-4053-4013-ba07-7a5c5a46872a" />

Tới đây thì ra được thời gian mà tiến trình đã thực thi nhưng mà vì khi export là utc+7 nên mình phải trừ bớt đi 7 tiếng

<img width="1530" height="272" alt="image" src="https://github.com/user-attachments/assets/fa085a02-f9c9-4d93-bf9d-e84d20c684ea" />

Task13:The attacker exfiltrated multiple sensitive files. When did the exfiltration start? (UTC)

Để có thể tìm được thời gian mà attacker đã đánh cắp dữ liệu ta quay lại với file log của teamviewer vì trước đó attacker đã cài malware thông qua teamviewer.

Tìm với từ khóa là sendfile

<img width="1392" height="697" alt="image" src="https://github.com/user-attachments/assets/4c2b4ab9-95bd-47fe-b6be-b025a4c93a59" />

Bởi vì múi giờ trong file log là utc+1 nên ta trừ hao đi 1 tiếng, có thể thấy file nhạy cảm đã được tuồn ra khỏi hệ thống vào lúc 2025-08-20 10:12:07:

<img width="1502" height="270" alt="image" src="https://github.com/user-attachments/assets/51408c80-8598-4056-bebf-1bb8bcbb9395" />



Task14: Before exfiltration, several files were moved to the staged folder. When was the Heisen-9 facility backup database moved to the staged folder for exfiltration?

Có vẻ như câu hỏi muốn tìm mốc thời gian (Timestamp) mà file Heisen-9 này được tạo ra hoặc bị copy vào bên trong thư mục flyover


Lọc với từ khóa Heisen-9 trong file csv 
<img width="1865" height="736" alt="image" src="https://github.com/user-attachments/assets/e73f62c6-fb95-4de9-8244-81af29db9514" />

Một chút logic của toàn bộ quá trình tấn công để dễ hình dung: Task 13 và 14

10:11:09 (UTC): Kẻ tấn công copy/di chuyển file database Heisen-9 vào thư mục tạm (staged folder) để gom hàng.

10:12:07 (UTC): Đúng 1 phút sau, hắn bắt đầu dùng TeamViewer để "tuồn" (exfiltrate) các file này ra ngoài.

Task 15:When did the attacker access and read a txt file, which was probably the output of one of the tools they brought, due to the naming convention of the file?
 
Câu hỏi này muốn thử thách khả năng tìm kiếm dấu vết truy cập tài liệu (file access) của kẻ tấn công. Khi attacker chạy tools mimikatz để trích xuất mật khẩu thì có vẻ như chúng đã lưu vào 1 file txt, vậy thì chỉ cần tìm kiếm với từ khóa txt trong file csv là được

<img width="1477" height="406" alt="image" src="https://github.com/user-attachments/assets/6931610c-0389-4e06-89bc-cccda7ed5f6e" />


Mình tìm ra được 1 file là dump.txt đc tạo vào 8/20/2025  10:08:06

<img width="1602" height="247" alt="image" src="https://github.com/user-attachments/assets/fbbaba77-6fc4-486c-ba75-56caf3e8204b" />


Task 16:The attacker created a persistence mechanism on the workstation. When was the persistence setup?

Câu hỏi này đang đề cập đến một khái niệm cốt lõi trong các cuộc tấn công mạng: Persistence (Cơ chế duy trì quyền truy cập/Trú ngụ lâu dài).Persistence là gì? Khi hacker đã xâm nhập thành công, chúng luôn lo sợ nạn nhân sẽ tắt máy, đăng xuất hoặc khởi động lại máy tính (những hành động này sẽ quét sạch các kết nối và mã độc đang chạy tạm thời trên RAM). Để "sống sót", chúng sẽ cấy mã độc vào các thành phần khởi động cố định của Windows

Ở bài lab này, kẻ tấn công đã can thiệp vào cấu hình đăng nhập (Winlogon), lén chèn thêm file thực thi của chúng (có tên là JM.exe) để nó tự động kích hoạt mỗi khi có người dùng đăng nhập vào máy.

Sau đó mình trích xuất Hive SOFTWARE trong thư mục C:\Windows\System32\config vì đây là nơi Windows lưu trữ toàn bộ cấu hình phần mềm hệ thống.Sau đó mở bằng registry explore và điều hướng tới thư mục sau Microsoft\Windows NT\CurrentVersion\Winlogon.

<img width="1007" height="511" alt="image" src="https://github.com/user-attachments/assets/17135b5e-ab5a-4f14-9dbf-fbfac39b4b68" />

Bình thường, hệ thống chỉ chạy mỗi Userinit.exe để khởi tạo môi trường khi người dùng đăng nhập. Việc hacker phẩy thêm , JM.exe vào đằng sau đồng nghĩa với việc: cứ mỗi lần có ai đó đăng nhập vào máy tính này, mã độc JM.exe sẽ tự động được kích hoạt chạy ngầm theo

<img width="1328" height="367" alt="image" src="https://github.com/user-attachments/assets/9447a111-78ed-407f-82a5-d47fba3da36b" />

Có vẻ như đây là thời gian attacker chèn mã độc vào hệ thống.

<img width="1492" height="300" alt="image" src="https://github.com/user-attachments/assets/cf201f11-ca09-4743-9e4e-d0ca86a976b1" />

Task 17: What is the MITRE ID of the persistence subtechnique?

ề bài muốn kiểm tra xem có biết hành vi "sửa khóa Userinit trong Registry Winlogon" được giới bảo mật gọi tên chính thức bằng mã ID nào không

Như chúng ta vừa phân tích ở câu trước, kẻ tấn công đã can thiệp vào khóa Winlogon để ép hệ thống tự động chạy file JM.exe mỗi khi người dùng đăng nhập (Logon).

Nếu lên trang chủ của MITRE ATT&CK và tìm kiếm từ khóa "Winlogon" hoặc "Userinit", sẽ thấy kỹ thuật này thuộc nhóm Boot or Logon Autostart Execution (T1547) và kỹ thuật phụ cụ thể dành riêng cho Winlogon Helper là .004

<img width="1437" height="298" alt="image" src="https://github.com/user-attachments/assets/8a786fe4-3fe8-4556-92ff-43fb8a5bd416" />

Task 18: When did the malicious RMM session end?

RMM (Remote Monitoring and Management): Là thuật ngữ chỉ chung các phần mềm hỗ trợ điều khiển và quản trị từ xa. Trong bài lab này, công cụ RMM bị hacker lợi dụng chính là TeamViewer. Mình cần xác định mốc thời gian chính xác (Timestamp) mà phiên điều khiển độc hại (malicious session) này bị đóng lại.

Trong thư mục log của TeamViewer, có một file chuyên dụng để ghi lại lịch sử kết nối đến có tên là Connections_incoming.txt.

<img width="1437" height="670" alt="image" src="https://github.com/user-attachments/assets/a96df5f7-20ee-4297-a522-dc05f1e9962c" />

<img width="1592" height="271" alt="image" src="https://github.com/user-attachments/assets/03f54f4d-7a32-4802-9333-6d4fc923ef8c" />

Task 19: The attacker found a password from exfiltrated files, allowing him to move laterally further into CogWork-1 infrastructure. What are the credentials for Heisen-9-WS-6?

File cơ sở dữ liệu mật khẩu Heisen-9 remote snapshot.kdbx bị tuồn qua TeamViewer ở các câu trước và có vẻ như task cuối muốn chúng ta tìm được user name và password

<img width="893" height="152" alt="image" src="https://github.com/user-attachments/assets/0111af40-c322-449a-8533-9d322c3d4575" />

Và có vẻ  như task cuối này chúng ta phải đi brute-force dùng keepass 2 john để lấy mã hash và dùng john the ripper để crack mật khẩu

Vì máy kali của mình lỗi mở không lên nên mình đi kiếm đáp án để hoàn thành labs nha.....


<img width="1533" height="371" alt="image" src="https://github.com/user-attachments/assets/43c2895e-7f26-46fe-9680-c22368356df4" />





















































