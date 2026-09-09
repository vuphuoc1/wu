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






