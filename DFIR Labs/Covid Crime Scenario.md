Covid Crime Scenario
Difficulty: Medium


Description
While the whole world is under the situation of COVID-19, we found out that illegal weapon trading was going on the black market, and confiscated the suspect secret_man's PC!

Q1:What is the tangential cipher used for illegal weapon trade?
Q2;What version of the browser does the suspect set as the default browser?

Flag format: flag{answer1_answer2}

Author
ws1004

<img width="1406" height="697" alt="image" src="https://github.com/user-attachments/assets/09223938-f803-4c60-a663-9675bbc230bc" />

Dùng FTK mở ra và sau đó mìn quyết định làm câu 2 trước, câu 2 muốn mình xác định phiên bản của trình duyệt mặc định là gì?

Đầu tiên mình phải xác định được trình duyệt mặc định, export file NTUSER.dat và kiểm tra các nhánh Userchoice:Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice

<img width="1917" height="947" alt="image" src="https://github.com/user-attachments/assets/626ca226-c948-40ee-8526-e25bace676ae" />


Xác định được trình duyệt mặc định là Googlechrome quay lại FTK để tìm version :

Mình tìm theo path sau: Users\secre\AppData\Local\Google\Chrome\Userdata\lastVersion

<img width="1917" height="1010" alt="image" src="https://github.com/user-attachments/assets/d81ad47a-9769-4976-96c1-0ad8806d2ead" />


Câu hỏi 1 có liên quan đến Tangential Ciphe ( giao dịch vũ khí) và ở đây là trong bối cảnh covid 19 nên mình nghĩ họ đã dùng 1 ứng dụng liên lạc từ xa và có thể là Zoom nên mình nghĩ mình sẽ kiểm tra lịch sử tin nhắn ở bên trong zoom , đầu tiên mình sẽ đi đến folder chứa profile của tài khoản zoom: C:\Users\secre\AppData\Roaming\Zoom\data\36hf7hjdtmsdyqpagtqcww@xmpp.zo

<img width="1852" height="711" alt="image" src="https://github.com/user-attachments/assets/32004d1e-f715-4652-9308-b336b5e2b3c0" />

Mình thu được ở đây 1 đống file database và thường format của các file này là SQL lite 3, ý tưởng ban đầu của mình sẽ là đưa vào Db browser for Sql lite để check lịch sử nhưng vấn đề là có nhiều file thì làm sao biết file nào đúng format?

Hướng giải quyết là trích hết và load vào db browser nhưng để định dạng sql lite 3 thì mình sẽ lọc được chỉ còn 1 file :

Và sau đây là lịch sử tin nhắn:

<img width="1917" height="560" alt="image" src="https://github.com/user-attachments/assets/4de46361-7338-4462-9c50-0c625fa666d7" />

Và mình chú ý vào đoạn tin nhắn này, có vẻ như " giao dịch vũ khí " ở trong file nào đó , mình sẽ xem cache của file :

<img width="1906" height="1018" alt="image" src="https://github.com/user-attachments/assets/236441d0-5b63-424a-afe6-0b320176e444" />

Vậy ra file đó là secret.txt , tìm cách đọc nội dung trong file đó là xong.


Mình tìm mãi mà không thấy, do nạn nhân đã tải file đó về nhưng dùng eraser xóa vĩnh viễn nên không khôi phục được, chỉ còn 1 cách là tìm lưu lại trên cloud nhưng bài này đã 6 năm rồi nên ở trên đó chắc cũng xóa nên mình phải lấy tạm flag.
Mr_K_1_W@nT_Cola!!
Ghép lại ta được flag{Mr_K_1_W@nT_Cola!!_83.0.4103.61}.










