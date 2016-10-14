Here I am going to explain the program briefly and see the outputs for different inputs. The detailed explanation is provided in the comments. The program includes three two main functions: 
  online_pcap: this function is called when we want to capture the packet from a device!
	It uses packet_analyzer function as a loop_back function.
	In fact, it is responsible for opening the device and setting the appropriate filter
	based on the user input and then calling the pcap_loop function.  
  offline_pcap:this function is called when we wants to analyze the traffic in the existing pcap file!
	Most part of this function is completely similar with  packet_analyzer function. 

Let's see the output of the program for different inputs! We first start with reading the pcap file for the homework 1!!

(1)

# ./mydump -r hw1.pcap | head -20
Sat Jan 12 11:37:42 2013 OTHER 111.155.192.168 -> 0.1.0.0 len 2048

Sat Jan 12 11:38:02 2013 UDP 192.168.0.1:1901 -> 239.255.255.250:1900 len 328
00000   4e 4f 54 49 46 59 20 2a  20 48 54 54 50 2f 31 2e    NOTIFY * HTTP/1.
00016   31 0d 0a 48 4f 53 54 3a  20 32 33 39 2e 32 35 35    1..HOST: 239.255
00032   2e 32 35 35 2e 32 35 30  3a 31 39 30 30 0d 0a 43    .255.250:1900..C
00048   61 63 68 65 2d 43 6f 6e  74 72 6f 6c 3a 20 6d 61    ache-Control: ma
00064   78 2d 61 67 65 3d 33 36  30 30 0d 0a 4c 6f 63 61    x-age=3600..Loca
00080   74 69 6f 6e 3a 20 68 74  74 70 3a 2f 2f 31 39 32    tion: http://192
00096   2e 31 36 38 2e 30 2e 31  3a 38 30 2f 52 6f 6f 74    .168.0.1:80/Root
00112   44 65 76 69 63 65 2e 78  6d 6c 0d 0a 4e 54 3a 20    Device.xml..NT: 
00128   75 75 69 64 3a 75 70 6e  70 2d 49 6e 74 65 72 6e    uuid:upnp-Intern
00144   65 74 47 61 74 65 77 61  79 44 65 76 69 63 65 2d    etGatewayDevice-
00160   31 5f 30 2d 63 34 33 64  63 37 31 37 36 66 39 62    1_0-c43dc7176f9b
00176   0d 0a 55 53 4e 3a 20 75  75 69 64 3a 75 70 6e 70    ..USN: uuid:upnp
00192   2d 49 6e 74 65 72 6e 65  74 47 61 74 65 77 61 79    -InternetGateway
00208   44 65 76 69 63 65 2d 31  5f 30 2d 63 34 33 64 63    Device-1_0-c43dc
00224   37 31 37 36 66 39 62 0d  0a 4e 54 53 3a 20 73 73    7176f9b..NTS: ss
00240   64 70 3a 61 6c 69 76 65  0d 0a 53 65 72 76 65 72    dp:alive..Server
00256   3a 20 55 50 6e 50 2f 31  2e 30 20 55 50 6e 50 2f    : UPnP/1.0 UPnP/

(2) Search word "Google" in the payload!!

# ./mydump -r hw1.pcap -s Google | head -20

Sun Jan 13 05:36:10 2013 TCP 192.168.0.200:42497 -> 91.189.90.40:80 len 464
00000   47 45 54 20 2f 31 31 2e  31 30 2f 47 6f 6f 67 6c    GET /11.10/Googl
00016   65 2f 3f 73 6f 75 72 63  65 69 64 3d 68 70 20 48    e/?sourceid=hp H
00032   54 54 50 2f 31 2e 31 0d  0a 48 6f 73 74 3a 20 73    TTP/1.1..Host: s
00048   74 61 72 74 2e 75 62 75  6e 74 75 2e 63 6f 6d 0d    tart.ubuntu.com.
00064   0a 55 73 65 72 2d 41 67  65 6e 74 3a 20 4d 6f 7a    .User-Agent: Moz
00080   69 6c 6c 61 2f 35 2e 30  20 28 58 31 31 3b 20 55    illa/5.0 (X11; U
00096   62 75 6e 74 75 3b 20 4c  69 6e 75 78 20 69 36 38    buntu; Linux i68
00112   36 3b 20 72 76 3a 31 37  2e 30 29 20 47 65 63 6b    6; rv:17.0) Geck
00128   6f 2f 32 30 31 30 30 31  30 31 20 46 69 72 65 66    o/20100101 Firef
00144   6f 78 2f 31 37 2e 30 0d  0a 41 63 63 65 70 74 3a    ox/17.0..Accept:
00160   20 74 65 78 74 2f 68 74  6d 6c 2c 61 70 70 6c 69     text/html,appli
00176   63 61 74 69 6f 6e 2f 78  68 74 6d 6c 2b 78 6d 6c    cation/xhtml+xml
00192   2c 61 70 70 6c 69 63 61  74 69 6f 6e 2f 78 6d 6c    ,application/xml
00208   3b 71 3d 30 2e 39 2c 2a  2f 2a 3b 71 3d 30 2e 38    ;q=0.9,*/*;q=0.8
00224   0d 0a 41 63 63 65 70 74  2d 4c 61 6e 67 75 61 67    ..Accept-Languag
00240   65 3a 20 65 6e 2d 55 53  2c 65 6e 3b 71 3d 30 2e    e: en-US,en;q=0.
00256   35 0d 0a 41 63 63 65 70  74 2d 45 6e 63 6f 64 69    5..Accept-Encodi
00272   6e 67 3a 20 67 7a 69 70  2c 20 64 65 66 6c 61 74    ng: gzip, deflat
00288   65 0d 0a 43 6f 6e 6e 65  63 74 69 6f 6e 3a 20 6b    e..Connection: k

(3) Use g flag to only see the http get and post request

# ./mydump -r hw1.pcap -g  | head -20

Sat Jan 12 22:30:48 2013 TCP 92.240.68.152:9485 -> 192.168.0.200:80 len 163
GET http://pic.leech.it/i/f166c/479246b0asttas.jpg

Sat Jan 12 22:30:49 2013 TCP 192.168.0.200:40341 -> 87.98.246.8:80 len 215
GET /i/f166c/479246b0asttas.jpg

Sat Jan 12 22:31:19 2013 TCP 92.240.68.152:17260 -> 192.168.0.200:80 len 193
GET http://ecx.images-amazon.com/images/I/41oZ1XsiOAL._SL500_AA300_.jpg

Sat Jan 12 22:31:19 2013 TCP 192.168.0.200:40630 -> 216.137.63.121:80 len 219
GET /images/I/41oZ1XsiOAL.

Sat Jan 12 22:31:50 2013 TCP 92.240.68.152:19957 -> 192.168.0.200:80 len 164
GET http://images4.byinter.net/DSC442566.gif

Sat Jan 12 22:31:50 2013 TCP 192.168.0.200:55528 -> 159.148.96.184:80 len 209
GET /DSC442566.gif

Sat Jan 12 22:32:21 2013 TCP 92.240.68.152:22272 -> 192.168.0.200:80 len 181
GET http://www.nature.com/news/2009/090527/images/459492a-i1.0.jpg


(4) Specify different filter expression!! Notice that there is only one icmp packet! If you test
with tcpdump you will get the same result!!

# ./mydump -r hw1.pcap 'icmp'

Mon Jan 14 12:42:31 2013 ICMP 1.234.31.20 -> 192.168.0.200 len 76
00000   45 00 00 30 00 00 40 00  2e 06 6a 5a c0 a8 00 c8    E..0..@...jZ....
00016   01 ea 1f 14 00 50 7b 81  bd cd 09 c6 3a 35 22 b0    .....P{.....:5".
00032   70 12 39 08 11 ab 00 00  02 04 05 b4 01 01 04 02    p.9.............


(5)(Combining features)
# ./mydump -r hw1.pcap -s Google -g

Sun Jan 13 05:36:10 2013 TCP 192.168.0.200:42497 -> 91.189.90.40:80 len 464
GET /11.10/Google/?sourceid=hp

Sun Jan 13 05:44:43 2013 TCP 192.168.0.200:52724 -> 91.189.89.88:80 len 464
GET /11.10/Google/?sourceid=hp

Sun Jan 13 05:45:22 2013 TCP 192.168.0.200:42503 -> 91.189.90.40:80 len 369
GET /11.10/Google/?sourceid=hp

Sun Jan 13 05:45:50 2013 TCP 192.168.0.200:58460 -> 91.189.90.41:80 len 419
GET /11.10/Google/?sourceid=hp


Now lets listen to user specified and default interface:

(1) Specifing the interface

#  ./mydump -i eth0 | head -n20

Mon Mar  9 21:21:21 2015 UDP 10.0.2.15:65240 -> 130.245.255.4:53 len 62
00000   e3 50 01 00 00 01 00 00  00 00 00 00 02 73 33 09    .P...........s3.
00016   61 6d 61 7a 6f 6e 61 77  73 03 63 6f 6d 00 00 01    amazonaws.com...
00032   00 01                                               ..

Mon Mar  9 21:21:21 2015 UDP 10.0.2.15:49990 -> 130.245.255.4:53 len 62
00000   aa 7e 01 00 00 01 00 00  00 00 00 00 02 73 33 09    .~...........s3.
00016   61 6d 61 7a 6f 6e 61 77  73 03 63 6f 6d 00 00 1c    amazonaws.com...
00032   00 01                                               ..

Mon Mar  9 21:21:21 2015 UDP 10.0.2.15:35459 -> 130.245.255.4:53 len 62
00000   8e ce 01 00 00 01 00 00  00 00 00 00 02 73 33 09    .............s3.
00016   61 6d 61 7a 6f 6e 61 77  73 03 63 6f 6d 00 00 01    amazonaws.com...
00032   00 01                                               ..

Mon Mar  9 21:21:21 2015 UDP 130.245.255.4:53 -> 10.0.2.15:49990 len 188
00000   aa 7e 81 80 00 01 00 02  00 01 00 00 02 73 33 09    .~...........s3.
00016   61 6d 61 7a 6f 6e 61 77  73 03 63 6f 6d 00 00 1c    amazonaws.com...
00032   00 01 c0 0c 00 05 00 01  00 00 0c b3 00 0b 02 73    ...............s
00048   33 05 61 2d 67 65 6f c0  0f c0 2e 00 05 00 01 00    3.a-geo.........

(2) Listening to default interface

# ./mydump  | head -n20

Mon Mar  9 21:26:01 2015 TCP 10.0.2.15:53984 -> 54.230.20.29:443 len 40

Mon Mar  9 21:26:01 2015 TCP 10.0.2.15:42512 -> 54.230.23.211:443 len 40

Mon Mar  9 21:26:01 2015 TCP 10.0.2.15:42513 -> 54.230.23.211:443 len 40

Mon Mar  9 21:26:01 2015 TCP 54.230.20.29:443 -> 10.0.2.15:53984 len 40

Mon Mar  9 21:26:01 2015 TCP 54.230.23.211:443 -> 10.0.2.15:42512 len 40

Mon Mar  9 21:26:01 2015 TCP 54.230.23.211:443 -> 10.0.2.15:42513 len 40

Mon Mar  9 21:26:01 2015 TCP 10.0.2.15:42556 -> 54.230.23.211:443 len 40

Mon Mar  9 21:26:01 2015 TCP 54.230.23.211:443 -> 10.0.2.15:42556 len 40

Mon Mar  9 21:26:01 2015 UDP 10.0.2.15:49849 -> 130.245.255.4:53 len 56
00000   08 c5 01 00 00 01 00 00  00 00 00 00 06 67 6f 6f    .............goo
00016   67 6c 65 03 63 6f 6d 00  00 01 00 01                gle.com.....


(3) Search "google" in the payload!! 

# ./mydump -s google | head -n20

Mon Mar  9 21:30:00 2015 UDP 10.0.2.15:3961 -> 130.245.255.4:53 len 60
00000   c9 c8 01 00 00 01 00 00  00 00 00 00 03 77 77 77    .............www
00016   06 67 6f 6f 67 6c 65 03  63 6f 6d 00 00 01 00 01    .google.com.....

Mon Mar  9 21:30:00 2015 UDP 10.0.2.15:42144 -> 130.245.255.4:53 len 60
00000   a7 53 01 00 00 01 00 00  00 00 00 00 03 77 77 77    .S...........www
00016   06 67 6f 6f 67 6c 65 03  63 6f 6d 00 00 1c 00 01    .google.com.....

Mon Mar  9 21:30:00 2015 UDP 130.245.255.4:53 -> 10.0.2.15:42144 len 88
00000   a7 53 81 80 00 01 00 01  00 00 00 00 03 77 77 77    .S...........www
00016   06 67 6f 6f 67 6c 65 03  63 6f 6d 00 00 1c 00 01    .google.com.....
00032   c0 0c 00 1c 00 01 00 00  00 28 00 10 26 07 f8 b0    .........(..&...
00048   40 06 08 0c 00 00 00 00  00 00 10 14                @...........

Mon Mar  9 21:30:00 2015 UDP 130.245.255.4:53 -> 10.0.2.15:3961 len 140
00000   c9 c8 81 80 00 01 00 05  00 00 00 00 03 77 77 77    .............www
00016   06 67 6f 6f 67 6c 65 03  63 6f 6d 00 00 01 00 01    .google.com.....
00032   c0 0c 00 01 00 01 00 00  01 29 00 04 ad c2 7b 53    .........)....{S
00048   c0 0c 00 01 00 01 00 00  01 29 00 04 ad c2 7b 50    .........)....{P
00064   c0 0c 00 01 00 01 00 00  01 29 00 04 ad c2 7b 54    .........)....{T

(4) Show only http get and post request!

# ./mydump -g

Mon Mar  9 21:33:28 2015 TCP 10.0.2.15:43188 -> 38.74.1.42:80 len 629
POST /Desktop/Login.aspx?t=50476475

Mon Mar  9 21:33:29 2015 TCP 10.0.2.15:43188 -> 38.74.1.42:80 len 629
POST /Desktop/Login.aspx?t=50476475

Mon Mar  9 21:33:30 2015 TCP 10.0.2.15:43188 -> 38.74.1.42:80 len 629
POST /Desktop/Login.aspx?t=50476475

Mon Mar  9 21:33:41 2015 TCP 10.0.2.15:43188 -> 38.74.1.42:80 len 655
POST /Desktop/Login.aspx?t=50476475

Mon Mar  9 21:33:41 2015 TCP 10.0.2.15:43188 -> 38.74.1.42:80 len 479
GET /static/css/theme.css


(5) Filter specification!!

# ./mydump 'tcp dst port 80'

Mon Mar  9 21:35:31 2015 TCP 10.0.2.15:43190 -> 38.74.1.42:80 len 40

Mon Mar  9 21:35:31 2015 TCP 10.0.2.15:43191 -> 38.74.1.42:80 len 40

Mon Mar  9 21:35:31 2015 TCP 10.0.2.15:43189 -> 38.74.1.42:80 len 40

Mon Mar  9 21:35:31 2015 TCP 10.0.2.15:43188 -> 38.74.1.42:80 len 40

Mon Mar  9 21:35:36 2015 TCP 10.0.2.15:43188 -> 38.74.1.42:80 len 40

Mon Mar  9 21:35:36 2015 TCP 10.0.2.15:43189 -> 38.74.1.42:80 len 40

Mon Mar  9 21:35:36 2015 TCP 10.0.2.15:43190 -> 38.74.1.42:80 len 40

Mon Mar  9 21:35:36 2015 TCP 10.0.2.15:43191 -> 38.74.1.42:80 len 40

Mon Mar  9 21:35:36 2015 TCP 10.0.2.15:43188 -> 38.74.1.42:80 len 40

Mon Mar  9 21:35:42 2015 TCP 10.0.2.15:43195 -> 38.74.1.42:80 len 655
00000   50 4f 53 54 20 2f 44 65  73 6b 74 6f 70 2f 4c 6f    POST /Desktop/Lo
00016   67 69 6e 2e 61 73 70 78  3f 74 3d 35 30 34 37 36    gin.aspx?t=50476
00032   34 37 35 20 48 54 54 50  2f 31 2e 31 0d 0a 48 6f    475 HTTP/1.1..Ho
00048   73 74 3a 20 77 77 77 2e  62 6c 6f 67 66 61 2e 63    st: www.blogfa.c
00064   6f 6d 0d 0a 55 73 65 72  2d 41 67 65 6e 74 3a 20    om..User-Agent: 
00080   4d 6f 7a 69 6c 6c 61 2f  35 2e 30 20 28 58 31 31    Mozilla/5.0 (X11
00096   3b 20 55 62 75 6e 74 75  3b 20 4c 69 6e 75 78 20    ; Ubuntu; Linux 
00112   78 38 36 5f 36 34 3b 20  72 76 3a 33 36 2e 30 29    x86_64; rv:36.0)
00128   20 47 65 63 6b 6f 2f 32  30 31 30 30 31 30 31 20     Gecko/20100101 
00144   46 69 72 65 66 6f 78 2f  33 36 2e 30 0d 0a 41 63    Firefox/36.0..Ac
00160   63 65 70 74 3a 20 74 65  78 74 2f 68 74 6d 6c 2c    cept: text/html,
00176   61 70 70 6c 69 63 61 74  69 6f 6e 2f 78 68 74 6d    application/xhtm
00192   6c 2b 78 6d 6c 2c 61 70  70 6c 69 63 61 74 69 6f    l+xml,applicatio
00208   6e 2f 78 6d 6c 3b 71 3d  30 2e 39 2c 2a 2f 2a 3b    n/xml;q=0.9,*/*;
00224   71 3d 30 2e 38 0d 0a 41  63 63 65 70 74 2d 4c 61    q=0.8..Accept-La
00240   6e 67 75 61 67 65 3a 20  65 6e 2d 55 53 2c 65 6e    nguage: en-US,en
00256   3b 71 3d 30 2e 35 0d 0a  41 63 63 65 70 74 2d 45    ;q=0.5..Accept-E
00272   6e 63 6f 64 69 6e 67 3a  20 67 7a 69 70 2c 20 64    ncoding: gzip, d
00288   65 66 6c 61 74 65 0d 0a  52 65 66 65 72 65 72 3a    eflate..Referer:
00304   20 68 74 74 70 3a 2f 2f  77 77 77 2e 62 6c 6f 67     http://www.blog
00320   66 61 2e 63 6f 6d 2f 44  65 73 6b 74 6f 70 2f 4c    fa.com/Desktop/L
00336   6f 67 69 6e 2e 61 73 70  78 3f 74 3d 35 30 34 37    ogin.aspx?t=5047
00352   36 34 37 35 0d 0a 43 6f  6e 6e 65 63 74 69 6f 6e    6475..Connection
00368   3a 20 6b 65 65 70 2d 61  6c 69 76 65 0d 0a 43 61    : keep-alive..Ca
00384   63 68 65 2d 43 6f 6e 74  72 6f 6c 3a 20 6d 61 78    che-Control: max
00400   2d 61 67 65 3d 30 0d 0a  43 6f 6e 74 65 6e 74 2d    -age=0..Content-
00416   54 79 70 65 3a 20 61 70  70 6c 69 63 61 74 69 6f    Type: applicatio
00432   6e 2f 78 2d 77 77 77 2d  66 6f 72 6d 2d 75 72 6c    n/x-www-form-url
00448   65 6e 63 6f 64 65 64 0d  0a 43 6f 6e 74 65 6e 74    encoded..Content
00464   2d 4c 65 6e 67 74 68 3a  20 31 33 35 0d 0a 0d 0a    -Length: 135....
00480   5f 74 78 3d 31 33 33 31  32 39 26 75 69 64 3d 61    _tx=133129&uid=a
00496   61 61 61 61 26 32 36 39  3d 61 61 61 61 61 61 26    aaaa&269=aaaaaa&
00512   62 74 6e 53 75 62 6d 69  74 3d 25 44 39 25 38 38    btnSubmit=%D9%88
00528   25 44 38 25 42 31 25 44  39 25 38 38 25 44 38 25    %D8%B1%D9%88%D8%
00544   41 46 2b 25 44 38 25 41  38 25 44 39 25 38 37 2b    AF+%D8%A8%D9%87+
00560   25 44 38 25 41 38 25 44  38 25 41 45 25 44 38 25    %D8%A8%D8%AE%D8%
00576   42 34 2b 25 44 39 25 38  35 25 44 38 25 41 46 25    B4+%D9%85%D8%AF%
00592   44 42 25 38 43 25 44 38  25 42 31 25 44 42 25 38    DB%8C%D8%B1%DB%8
00608   43 25 44 38 25 41 41                                C%D8%AA


(6) using s and g flags together!!

# ./mydump -g -s Mozilla

Mon Mar  9 21:38:48 2015 TCP 10.0.2.15:43203 -> 38.74.1.42:80 len 655
POST /Desktop/Login.aspx?t=50476475

Mon Mar  9 21:38:48 2015 TCP 10.0.2.15:43203 -> 38.74.1.42:80 len 479
GET /static/css/theme.css

Mon Mar  9 21:38:48 2015 TCP 10.0.2.15:43204 -> 38.74.1.42:80 len 493
GET /images/blogfa.gif

Mon Mar  9 21:38:48 2015 TCP 10.0.2.15:43203 -> 38.74.1.42:80 len 485
GET /static/theme/bg.jpg

Mon Mar  9 21:38:48 2015 TCP 10.0.2.15:43204 -> 38.74.1.42:80 len 487
GET /static/theme/topM.jpg

Mon Mar  9 21:38:48 2015 TCP 10.0.2.15:43203 -> 38.74.1.42:80 len 488
GET /static/theme/leftM.jpg

Mon Mar  9 21:38:48 2015 TCP 10.0.2.15:43205 -> 38.74.1.42:80 len 485
GET /static/theme/tlC.gif

Mon Mar  9 21:38:48 2015 TCP 10.0.2.15:43206 -> 38.74.1.42:80 len 486
GET /static/theme/trC.gif

Mon Mar  9 21:38:48 2015 TCP 10.0.2.15:43204 -> 38.74.1.42:80 len 489
GET /static/theme/rightM.jpg

Mon Mar  9 21:38:48 2015 TCP 10.0.2.15:43207 -> 38.74.1.42:80 len 493
GET /static/theme/trGradient.png

Mon Mar  9 21:38:48 2015 TCP 10.0.2.15:43208 -> 38.74.1.42:80 len 489
GET /static/theme/menubg.gif

Mon Mar  9 21:38:49 2015 TCP 10.0.2.15:43203 -> 38.74.1.42:80 len 486
GET /static/theme/hbox.gif


(7) Same example with specified interface!

#  ./mydump -i eth0 -g -s Mozilla

Mon Mar  9 21:40:40 2015 TCP 10.0.2.15:43203 -> 38.74.1.42:80 len 655
POST /Desktop/Login.aspx?t=50476475

Mon Mar  9 21:40:40 2015 TCP 10.0.2.15:43203 -> 38.74.1.42:80 len 479
GET /static/css/theme.css

Mon Mar  9 21:40:41 2015 TCP 10.0.2.15:43204 -> 38.74.1.42:80 len 493
GET /images/blogfa.gif

Mon Mar  9 21:40:41 2015 TCP 10.0.2.15:43203 -> 38.74.1.42:80 len 485
GET /static/theme/bg.jpg

Mon Mar  9 21:40:41 2015 TCP 10.0.2.15:43205 -> 38.74.1.42:80 len 487
GET /static/theme/topM.jpg

Mon Mar  9 21:40:41 2015 TCP 10.0.2.15:43206 -> 38.74.1.42:80 len 488
GET /static/theme/leftM.jpg

Mon Mar  9 21:40:41 2015 TCP 10.0.2.15:43207 -> 38.74.1.42:80 len 485
GET /static/theme/tlC.gif

Mon Mar  9 21:40:41 2015 TCP 10.0.2.15:43208 -> 38.74.1.42:80 len 486
GET /static/theme/trC.gif

Mon Mar  9 21:40:41 2015 TCP 10.0.2.15:43204 -> 38.74.1.42:80 len 489
GET /static/theme/rightM.jpg

Mon Mar  9 21:40:41 2015 TCP 10.0.2.15:43205 -> 38.74.1.42:80 len 493
GET /static/theme/trGradient.png

Mon Mar  9 21:40:41 2015 TCP 10.0.2.15:43203 -> 38.74.1.42:80 len 489
GET /static/theme/menubg.gif

Mon Mar  9 21:40:41 2015 TCP 10.0.2.15:43203 -> 38.74.1.42:80 len 486
GET /static/theme/hbox.gif




