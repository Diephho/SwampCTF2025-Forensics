# SwampCTF 2025
## Forensics

### Homework Help
<p align="center">
  <img src="https://hackmd.io/_uploads/H1TyuQS6ke.png" width="60%">
</p>
Resouce: SWAMP_D_image.zip

In this chall, I got a **.vhd (Virtual Hard Disk)** file. So I open it with **FTK Imager**.

![image](https://hackmd.io/_uploads/ByKvK7H6ye.png)

The request is related to some notes so I first check folder *School* for a little bit infomation

![image](https://hackmd.io/_uploads/HJchY7Ba1e.png)

In the *Hacking* folder, it seem likes it is the note that we need to find. I focus on **Hacking Notes.docx** that have Size:14, it is a file that was deleted but not erasing completely.

I try to export this file, open it and get the flag
![image](https://hackmd.io/_uploads/Hyvucmrpkx.png)

**FLAG: swampCTF{n0thing_i5_3v3r_d3l3t3d}**

### Preferential Treatment
<p align="center">
  <img src="https://hackmd.io/_uploads/SJfbs7rTkl.png" width="60%">
</p>
Resouce: gpnightmare.pcap

It is a pcacp file. First, open it with Wireshark
![image](https://hackmd.io/_uploads/B1v_sQST1l.png)

We get some SMB packets, that maybe something hidden under this protocol. Following TCP stream to have more infomation

![image](https://hackmd.io/_uploads/SJWgnQH6Je.png)

We got some xml data with cpassword was encrypted. Searching a little bit in Internet, i found that `cpassword` was encrypted using AES-256 with fixed key (published by Microsoft).
So I decrypted it with **gpp-decrypt** tool and got the flag
![image](https://hackmd.io/_uploads/SkOA07B61x.png)

**FLAG: swampCTF{4v3r463_w1nd0w5_53cur17y}**

### Planetary Storage
<p align="center">
  <img src="https://hackmd.io/_uploads/SkczJ4Hpke.png" width="60%">
</p>
Resource: PlanetaryStorage.zip

Unzip this file, I got some locked .ldb files and a LOG file
![image](https://hackmd.io/_uploads/rybqJEBaJl.png)

First, i check the LOG file.
![image](https://hackmd.io/_uploads/HkEBEVrpJl.png)

Ok, it seem like this man open L0@2 and write some data, repeat with L0@7 and L0@10. And we got 000002.ldb, 000007.ldb, 000010.ldb. Information maybe was divided into each file.

About .ldb files, I searched and it related to LevelDB, something about OrbitDB, hmmm. First, I just used `strings` to read it
![image](https://hackmd.io/_uploads/B1gvH4B61g.png)

This had a record (L0@2), with field /_localHeads, and the payload is so sus, it's in base64. Let decrypt it

![image](https://hackmd.io/_uploads/BJVzINSpkg.png)

I got some base64 in base64, so continue decrypt one more time with new base64
![image](https://hackmd.io/_uploads/rJOLUVr6Jg.png)

I got some words, it is the information was written into L0@2. So I check L0@7 and L0@10 in the same way. Yeah, payload in L0@10 gave me the flag
![image](https://hackmd.io/_uploads/BypTI4Baye.png)

**FLAG: swampCTF{1pf5-b453d-d474b453}**

### MuddyWater
<p align="center">
  <img src="https://hackmd.io/_uploads/H1KPPVB6Jx.png" width="60%">
</p>
Resource: muddywater.pcap

Requests related to brute force login and requests to find successfully logged in usernames and passwords.

Open pcap file and it got a lot of **SMB** packets
![image](https://hackmd.io/_uploads/HkUku4rTke.png)

Using filter to remove packets that cause error action with quite sus option: 
```
((((smb2.session_flags == 0x0000)) && !(smb2.security_blob == "")) && !(smb2.security_blob == a1:82:01:0b:30:82:01:07:a0:03:0a:01:01:a1:0c:06:0a:2b:06:01:04:01:82:37:02:02:0a:a2:81:f1:04:81:ee:4e:54:4c:4d:53:53:50:00:02:00:00:00:1e:00:1e:00:38:00:00:00:05:02:8a:a2:c6:09:ad:1b:3a:15:ae:dc:00:00:00:00:00:00:00:00:98:00:98:00:56:00:00:00:0a:00:61:4a:00:00:00:0f:44:00:45:00:53:00:4b:00:54:00:4f:00:50:00:2d:00:30:00:54:00:4e:00:4f:00:45:00:34:00:56:00:02:00:1e:00:44:00:45:00:53:00:4b:00:54:00:4f:00:50:00:2d:00:30:00:54:00:4e:00:4f:00:45:00:34:00:56:00:01:00:1e:00:44:00:45:00:53:00:4b:00:54:00:4f:00:50:00:2d:00:30:00:54:00:4e:00:4f:00:45:00:34:00:56:00:04:00:1e:00:44:00:45:00:53:00:4b:00:54:00:4f:00:50:00:2d:00:30:00:54:00:4e:00:4f:00:45:00:34:00:56:00:03:00:1e:00:44:00:45:00:53:00:4b:00:54:00:4f:00:50:00:2d:00:30:00:54:00:4e:00:4f:00:45:00:34:00:56:00:07:00:08:00:6f:23:3d:3d:9f:9e:db:01:00:00:00:00)) && !(frame.len == 401)
```

![image](https://hackmd.io/_uploads/HyvwT4Spke.png)

Finally, I got the packet that logon was success. Next, Follow this tcpstream to find the username
![image](https://hackmd.io/_uploads/Syx3aNSp1e.png)

Yah, username is **"hackbackzip"**. Now, time to trace the password.

Time for searching, I saw that *NTLM do not send plaintext password, client send NTLMv2 hash response*. So I will need to extract NTLMv2 hash and use hashcat to brute-force the password

![image](https://hackmd.io/_uploads/H1dqyBB6yl.png)

From NTLMSSP_AUTH packet, extract **NT Proof String and NTLMv2 Blob**

**Format for hashcat:**
```
hackbackzip::DESKTOP-0TNOE4V:d102444d56e078f4:eb1b0afc1eef819c1dccd514c9623201:01010000000000006f233d3d9f9edb01755959535466696d0000000002001e004400450053004b0054004f0050002d00300054004e004f0045003400560001001e004400450053004b0054004f0050002d00300054004e004f0045003400560004001e004400450053004b0054004f0050002d00300054004e004f0045003400560003001e004400450053004b0054004f0050002d00300054004e004f00450034005600070008006f233d3d9f9edb010900280063006900660073002f004400450053004b0054004f0050002d00300054004e004f004500340056000000000000000000
```

![image](https://hackmd.io/_uploads/BJgkGrBpkx.png)
![image](https://hackmd.io/_uploads/Hkp-GSSaye.png)

**Found password: pikeplace**

**FLAG: swampCTF{hackbackzip:pikeplace}**

### Proto Proto
<p align="center">
  <img src="https://hackmd.io/_uploads/B1KSmHSTye.png" width="60%">
</p>

Resource: proto_proto.pcap
Host: chals.swampctf.com:44254

Hmm, another pcap... From description, it is related client-server communication. Let me open it
![image](https://hackmd.io/_uploads/rJE3mrBTJl.png)

I see some TLS, STP packets and some UDP packets. Follow UDP stream, I saw that UDP is the protocol to send flag. The flag in this is `fake` :cry: 
![image](https://hackmd.io/_uploads/BkiNrvvpJx.png)

I remembered about the host in this chall. But netcat was refused to connect. So I need preparation. Back to Wireshark, I checked the packet sent to server, and the response was fake flag
![image](https://hackmd.io/_uploads/B1LMIwDa1g.png)

The connection we need is: protocol:UDP, hostname:chals.swampctf.com, port:44254, Data: 0208666c61672e747874
```python
import socket

# Target server details
HOST = "chals.swampctf.com"
PORT = 44254

# Hex data to send (convert to bytes)
hex_data = "0208666c61672e747874"
data = bytes.fromhex(hex_data)

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    # Send the data
    sock.sendto(data, (HOST, PORT))
    print(f"Sent: {hex_data}")
    
    # Receive response (optional, depends on challenge behavior)
    response, addr = sock.recvfrom(1024)
    print(f"Received: {response}")

except Exception as e:
    print(f"Error: {e}")

finally:
    sock.close()
```
![image](https://hackmd.io/_uploads/BJqcvvvpJx.png)

**FLAG: swampCTF{r3v3r53_my_pr070_l1k3_m070_m070}**

## Misc
### Pretty Picture: Double Exposure
<p align="center">
  <img src="https://hackmd.io/_uploads/ByDigLSpyg.png" width="60%">
</p>

Open with StegOnline with option LSB Half
![image](https://hackmd.io/_uploads/rJlMZIBTyg.png)

Use some bit browse for full flag
![image](https://hackmd.io/_uploads/SJyV-Irp1g.png)

**FLAG: swampCTF{m3ss4g3s_0r_c0de_c4n_b3_h1dd3n_1n_1m4g3s}**

## Osint time~

### Party Time!
<p align="center">
  <img src="https://hackmd.io/_uploads/ry64DSHTyx.png" width="60%">
</p>

I got a picture .HEIC file, just open it and see a place in map, seriuously?
![image](https://hackmd.io/_uploads/BygwPBHpkl.png)

Use **exiftool** and I got **GPS Latitude and Longitude**

![image](https://hackmd.io/_uploads/HyaDiSSpJe.png)

Just convert or put it in to google map
![Screenshot 2025-03-29 172055](https://hackmd.io/_uploads/rJz9srBpJl.png)

**FLAG: swampCTF{29.65,82.33}**

### On Thin Ice
<p align="center">
  <img src="https://hackmd.io/_uploads/rJWdpBr6Jl.png" width="60%">
</p>
Resouce: blank.jpg
![blank](https://hackmd.io/_uploads/BJOkxPwTke.jpg)

we got a .jpg file with just in black, and I just open Description of this file, some hex text is appeared
![image](https://hackmd.io/_uploads/Sy4LeDPpJe.png)

Decode this, I got some Russia text `Ӧкмысӧд воськов. Мездлун.`
![image](https://hackmd.io/_uploads/H1qhePDTyx.png)

Let translate this to English, I was suggested by Google Translate that this is Komi language and the text is `Step eight. Freedom.`
![image](https://hackmd.io/_uploads/SJ7J-wPTJx.png)
Just google it~
![image](https://hackmd.io/_uploads/S1gEWwvpyg.png)
We know that this language belonging to Komi, Russia. Some youtube videos were related to that, and those words is from "Call of Duty Black Ops". Looking at, I had two doubt words: Reznov and Vorkuta. I used Google Map, Reznov was inavailable, but Vorkuta was - a city in Komi Republic, Russia.
![image](https://hackmd.io/_uploads/HklnRzDvT1l.png)

And just search the ice rink, there is only one ice rink in this town, filter "Newest" Reviews and get the flag
![image](https://hackmd.io/_uploads/B1EPmwvTkx.png)

**FLAG: swampCTF{ForUM4sOnN0tForM3}**


### Party Time! Level 2
<p align="center">
  <img src="https://hackmd.io/_uploads/H1fFhHr61x.png" width="60%">
</p>

We got this house in last part, search ***"fast-food-restaurants"*** and the nearest place I see is ***"Checkers"***. Sort **"Newest"** in *Reviews*, I got the flag
![image](https://hackmd.io/_uploads/SJOg6rr6kx.png)

**FLAG: swampCTF{Checkers_Yum}**



