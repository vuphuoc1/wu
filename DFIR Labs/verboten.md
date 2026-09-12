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





Q3) What is the hash of the malware that the executable in the usb downloaded which persisted even after the efforts to remove the malware?
Format: verboten{md5{malware_executable)}

<img width="1891" height="502" alt="image" src="https://github.com/user-attachments/assets/f231932b-8c25-43ed-92d3-f1faa13a4839" />

Có vẻ như malware này chỉ đóng vai trò dropper/downloader và nó tải về 1 payload độc hại là Agent Tesla và đề bài yêu cầu mã md5 này

verboten{7b42afaa8d13acf084d3784cbc0bd4c2}






