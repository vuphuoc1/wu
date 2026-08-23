Description
The police organized a surprise attack to catch the hacker along with all the exhibits at the scene. However, the hacker had foreseen that, so he encrypted his secret file before that. He even sarcastically said "you are too stupid to decrypt my 2-layer security"

Note: This challenge doesn't have any questions but the flag itself!
Sau khi tải về và unzip thì mình được 3 file như sau và nhận được cảnh báo từ windows defenders nên chắc chắn file zip có chứa mã độc.

<img width="1555" height="254" alt="image" src="https://github.com/user-attachments/assets/7545de30-f592-4770-a8e1-9b7fe603f6b9" />

Sau đó mình đưa sang máy ảo để unzip thì thu được như này

<img width="1204" height="758" alt="image" src="https://github.com/user-attachments/assets/31f0efa0-b789-4c97-a319-34a5aa65760d" />

Mình chú ý đến 1 file txt tương dối khả nghi

<img width="881" height="305" alt="image" src="https://github.com/user-attachments/assets/3f1a371a-be75-4717-a2c8-bfa20e7d7fd6" />




<img width="1916" height="309" alt="image" src="https://github.com/user-attachments/assets/6a6108d7-a3fa-4604-aa15-521e3e67763c" />


Có thể thấy chuỗi đã được làm rối và là 1 mã độc powershell

Toàn bộ payload thực sự đã bị nén bằng thuật toán Deflate (System.IO.Compression.DeflateStream), sau đó mã hóa Base64 thành một chuỗi khổng lồ. Lệnh PowerShell này sẽ giải mã Base64, giải nén và ném thẳng mã độc vào bộ nhớ để chạy.Sau khi load payload vào bộ nhớ, script gọi một hàm tên là Encryption để mã hóa thư mục/file ./T3C4U

Giờ mình tiếp tục giải mã chuỗi base64 bằng cyberchef

<img width="1535" height="861" alt="image" src="https://github.com/user-attachments/assets/a9d1bfb7-ff75-441d-b968-68fddf444b61" />

Mình thu được đoạn mã sau
```
iEX ((("{40}{19}{25}{46}{15}{11}{41}{20}{14}{48}{33}{47}{37}{35}{2}{1}{31}{23}{18}{8}{45}{9}{39}{28}{24}{43}{38}{27}{53}{13}{36}{49}{16}{30}{17}{26}{21}{12}{0}{51}{4}{6}{10}{50}{5}{32}{34}{52}{42}{22}{29}{3}{44}{7}"-f '        }

        YPMencryptor = YPMaesMan','aged = New-Object System.Security.Cryptograp','  YPMaesMan','{
        YPMshaManaged.Dispose()
 ','r()
        YPMencryptedBytes = YPMencryptor.TransformFinal','edBytes
        YPMaesManaged.Dispose()
                
        if (YPMPath) {
         ','Block(YPMplainBytes, 0, YPMplainBytes.Length)
        YPMen','se()
    }
}','raphy.CipherMode]::CBC
','ed.Padding = [System.Security.Cryptography.PaddingMode]::Z','cryptedBytes = YPMaesManaged','m
    (','::ReadAllBytes(YPMFile.FullName)
            YPMoutPath = YPMFile.FullName + jnO.SOSjnO
','sEOk))
                
        if (Y','arameterSetName = jnOCryptFilejnO)]
        [String]YPMPath
    )

    Begin {
        YPMshaMan','ra','M','
             ','ystem.Security.Cryptog','()]
    [Outpu','(Mandatory = YPMtrue, P',' = [System.IO.File]','e
            return jnOFile encrypted to YPMoutP','d
        YPMaesManaged.Mode = [S','sManaged.BlockSize','t','   Write-Error -Message jnOFile not found!jnO
                break
            }
            YPMplainBytes',' ','      YPMae','athjnO
        }
    }


    End ','Path -ErrorAction SilentlyContinue
            if (!YPMFile.FullName) {
','hy.AesManage','   [System.IO.File]::WriteA','stem.','llBytes(YPMoutPath, YPMencryptedBytes)
      ','256Managed
      ','PMPath) {
            YPMFile = G','ography.SHA','28
','eros
  ','function Encryption {
    [CmdletBinding','
        [Parameter','= YPMFile.LastWriteTim',' = 1','       YPMaesManaged.Dispo','
        YPMaesManag','Type([string])]
    Pa','Security.Crypt','aged = New-Object Sy','et-Item -Path YP','.IV + YPMencrypt','aged.CreateEncrypto','      (Get-Item YPMoutPath).LastWriteTime ','       YPMaesManaged.KeySize = 256
    }

    Process {
        YPMaesManaged.Key = YPMshaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(EOkYPMencryptedByte')).rePlace(([cHaR]69+[cHaR]79+[cHaR]107),[STRInG][cHaR]39).rePlace(([cHaR]106+[cHaR]110+[cHaR]79),[STRInG][cHaR]34).rePlace(([cHaR]89+[cHaR]80+[cHaR]77),[STRInG][cHaR]36) ) 
```
Khi dịch ngược toàn bộ cấu trúc mảng và áp dụng các quy tắc thay thế , chúng ta thu được mã nguồn hoàn chỉnh của hàm mã hóa như sau:
```
function Encryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        # KHÓA BÍ MẬT NẰM Ở ĐÂY
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes('$encryptedByte'))
        
        $encryptor = $aesManaged.CreateEncryptor()
        
        if ($Path) {
            $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
            if (!$File.FullName) {
                Write-Error -Message "File not found!"
                break
            }
            $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
            $outPath = $File.FullName + ".SOS"
            $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
            
            # Ghi IV vào đầu file, sau đó đến dữ liệu đã mã hóa
            $encryptedBytes = $aesManaged.IV + $encryptedBytes
            [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
            
            # Giữ nguyên thời gian sửa đổi file
            (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
            
            return "File encrypted to $outPath"
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}
```
Từ đoạn mã trên chúng ta có thể thấy file T3C4U đã được mã hóa bằng thuật toán AES với key:$encryptedBytes IV là 16 byte đầu tiên của file .SOS

Sau 1 lúc tìm kiếm thì mình tìm thấy file Recyle.bin trong thư mục: home/kalilinux/Desktop

<img width="828" height="482" alt="image" src="https://github.com/user-attachments/assets/4020bd5e-8ab5-46a7-8658-8844ae185c08" />

Tiếp đến mình tìm vào file lịch sử dòng lệnh là file zsh.history

<img width="1486" height="723" alt="image" src="https://github.com/user-attachments/assets/a45b4b1b-4a22-494f-bcbc-e8e5b606800e" />


Thu được kết quả như sau

<img width="931" height="526" alt="image" src="https://github.com/user-attachments/assets/51e597c8-851b-4002-8e42-dd7fe1810946" />

Hacker tạo khóa GPG tên là VNvodich, sau đó dùng nó để mã hóa file PDF:
gpg -er VNvodich RestrictedAccess.pdf

(Kết quả sinh ra file RestrictedAccess.pdf.gpg)

Hacker đổi tên file .gpg đó thành một chuỗi 5 ký tự ngẫu nhiên (tr -dc 'a-zA-Z0-9' | fold -w 5) và 5 kí tự ngẫu nhiên đó chính là T3C4U

Hacker mở PowerShell (pwsh), chạy đoạn mã độc Base64 để mã hóa file T3C4U thành T3C4U.SOS

Và sau đó dùng lệnh mv để đổi tên file thành Recycle.bin

Mình sẽ viết 1 script python để giải mã:
```
import hashlib
from Cryptodome.Cipher import AES
import os

input_file = 'recycle.bin'
output_file = 'T3C4U_decrypted.gpg'
passphrase = "$encryptedBytes"

print(f"[*] Đang giải mã AES cho file: {input_file}")

try:
    key = hashlib.sha256(passphrase.encode('utf-8')).digest()

    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    # Tách 16 byte IV ở đầu file
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)

    # Cắt bỏ các byte padding \x00
    decrypted_data = decrypted_data.rstrip(b'\x00')

    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

    print(f"[+] Hoàn tất! Đã xuất ra file: {output_file}")
    print("[*] Kiểm tra định dạng file:")
    os.system(f"file {output_file}")

except Exception as e:
    print(f"[-] Lỗi: {e}")
```

<img width="991" height="379" alt="image" src="https://github.com/user-attachments/assets/a25a3872-5635-470b-99a4-b8b1fb055b17" />

Sau đó chạy lệnh: gpg --homedir "/home/kali/Downloads/home/kalilinux/.gnupg" -d T3C4U_decrypted.gpg > RestrictedAccess.pdf

Qua đó thu được flag

<img width="1756" height="821" alt="image" src="https://github.com/user-attachments/assets/996ff38f-3b7c-46c6-8678-1c04d465fab7" />

Flag:idek{Cr34t1n9_ch4ll3ngEs_6_d4ys_6_n1gts_w1th0ut_sl33p}















