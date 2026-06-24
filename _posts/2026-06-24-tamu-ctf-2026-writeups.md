---
title: "Writeups TAMU CTF 2026"
date: 2026-06-24 00:00:00 +0700
categories: [CTF Writeups]
tags: [ctf, tamu-ctf-2026, web, writeup]
---

🥸 Author: Halibut

# I. Web Exploitation

![image.png](/assets/img/ctf/tamu-ctf-2026/image.png)

Khởi động với một bài web, đầu tiên phải mở thử web lên xem có gì hot. 

Là tài liệu cho CLB, mình sẽ omverexplained nhiều chút với mục đích vừa đọc vừa học thêm kiến thức mới.

![image.png](/assets/img/ctf/tamu-ctf-2026/image%201.png)

Đây là một trang web cho phép mình upload file video hoặc file GIF. Back-end sẽ xử lý như nào đó để tách từng frame một của file mình upload ra, trả về Front-end để JavaScript hiển thị các frame này dưới dạng ASCII art video lên ô vuông xanh ở giữa.

Mình có thể xem hàm Frontend Javascript đó xử lý ASCII art này bằng công cụ Devtool, mặc dù nó không phục vụ cho bài CTF này cho lắm.

Để giải bài này, ta tiếp tục đọc mã nguồn Back-end mà đề bài cung cấp.

![image.png](/assets/img/ctf/tamu-ctf-2026/image%202.png)

**Đầu tiên là file `Dockerfile`** 

Vì máy chủ chạy trong container, file này dùng để định nghĩa môi trường của server (tức là ghi lại những gì server cần để cài đặt theo từng bước, từ ngoài vào trong).

```bash
FROM fedora:latest
```

- Lấy file image của hệ điều hành tên **Fedora** với phiên bản mới nhất làm nền tảng
- Fedora là một bản phân phối Linux của Red Hat, dùng `dnf` để làm trình quản lý gói.

```bash
RUN dnf install -y httpd python3 python3-pip ffmpeg mod_wsgi openssl && \
pip3 install flask werkzeug
```

sử dụng trình quản lý gói `dnf` để cài đặt các packet bao gồm:

- `httpd` này là Apache web server
- `python3` + `python3-pip` Môi trường Python
- `ffmpeg` Phần mềm xử lý video/GIF → trích xuất frames
- `mod_wsgi` Cầu nối giữa Apache Web Server ↔ Python Flask App
- `openssl` Tạo số random cho tên file flag (tránh người chơi share flag đi linh tinh)

sử dụng trình quản lý gói `pip3` của python để cài đặt các packet bao gồm:

- `flask` + `werkzeug` Thư viện lập trình web của Python

⇒ Có thể biết được gì từ những thông tin này? hệ thống này sử dụng phần mềm `ffmpeg` để biến đổi video của bạn thành → frame by frame.

⇒ sử dụng Apache web server và thư viện flask của python.

```bash
RUN mkdir -p /srv/app /srv/http/uploads/admin /srv/http/static/frames/shared/bad-apple
```

Dòng này nói về việc tạo một số thư mục bổ sung trong hệ thống bằng câu lệnh `mkdir` :

- `/srv/app` → chứa code xử lý của web app
- `/srv/http/uploads/admin` → bên trong admin kia có thể chứa file **gì đó**
- `/srv/http/static/frames/shared/bad-apple` → chứa frames GIF mẫu

→ Tại sao đọc đến đây, mình đã biết những file này sẽ chứa gì? Docker mới chỉ tạo ra chúng thôi mà? Thực ra là do mình đã đọc những dòng tiếp theo.

```bash
COPY wsgi_app.py /srv/app/wsgi_app.py
COPY templates/ /srv/app/templates/
```

→ Copy file `wsgi_app.py` và nội dung của một file templates nào đó bên ngoài vào thư mục `/srv/app/` bên trong Container.

```bash
COPY uploads/ /srv/http/uploads/
COPY bad-apple-frames/ /srv/http/static/frames/shared/bad-apple/
COPY .htpasswd /srv/http/.htpasswd
COPY httpd-append.conf /tmp/httpd-append.conf
```

→ Copy nội dung thư mục uploads vào `/srv/http/uploads/`

→ Copy từng frame của video [Bad Apple](https://www.youtube.com/watch?v=FtutLA63Cp8) vào thư mục `/srv/http/static/frames/shared/bad-apple/` để làm nội dung mặc định ban đầu khi bạn vừa mở web lên.

→ Copy file chứa thống tin đăng nhập mật khẩu gì đó `.htpasswd` vào `/srv/http/.htpasswd` (Không biết file mật khẩu này để làm gì?)

→ Copy file cấu hình `httpd-append.conf` vào `/tmp/httpd-append.conf`

***Khả năng cao cờ nằm trong thư mục upload đã được copy vào `/srv/http/uploads/` kia, vì các thư mục khác đều là up ảnh và up cấu hình hệ thống, riêng uploads là mình ko biết có gì trong ấy.***

Các thư mục được sử dụng để copy là các thư mục mà người ra đề đã chuẩn bị trước.

Tiếp theo, là cấu hình server apache:

```bash
RUN cat /tmp/httpd-append.conf >> /etc/httpd/conf/httpd.conf && \
    chmod -R 755 /srv/http/uploads /srv/http/static && \
    chown -R apache:apache /srv/app /srv/http
```

tại sao phải dùng `cat` để hiện ra nội dung file config trước rồi mới truyền nội dung của file config đó (`>>`) vào `/etc/httpd/conf/httpd.conf`  → Mục đích là để đề phòng file `httpd.conf` đã có các cấu hình cần thiết trước đó, mình sẽ phải nối thêm nội dung vào file gốc chứ ko thay thế nội dung cũ hoàn toàn.

Sau đó sẽ cấp quyền các thứ cho file config này bằng `chmod` và `chown`.

Cuối cùng là chạy server lên:

```bash
EXPOSE 80

CMD ["sh", "-c", "HEX=$(openssl rand -hex 16) && mv /srv/http/uploads/admin/flag.gif /srv/http/uploads/admin/$HEX-flag.gif && echo $HEX > /srv/http/.flag_secret && httpd -DFOREGROUND"]
```

OK, vậy là khi đọc xong file docker này, mình rút được một số thông tin quan trọng. 

1. Web server mà hệ thống này dùng là Apache còn mã nguồn web app sẽ sử dụng Python Flask.
2. Có một file upload đã được copy vào `/srv/http/uploads/` có thể chứa gì đó.
3. Web sử dụng `ffmpeg` để xử lý video/GIF thành từng frame một.

Giải thích 1 chút, trong thư viện lập trình web Flask của python, **có một hàm hỗ trợ cho code trở thành server giống Apache được tích hợp sẵn**, nhưng nó chỉ dành cho môi trường phát triển, không phải môi trường thực tế. Chính Flask cũng cảnh báo điều này: "Do not use the development server in a production environment”

Đó là lý do hệ thống web CTF này sẽ ko sử dụng server tích hợp đó, mà nó sẽ sử dụng Apache, ta sẽ có hệ thống như này: 

```bash
Internet
↓
Apache server
↓
mod_wsgi (trung gian, điều hướng về Flask app)
↓
Flask App
↓
Database, logic...
```

→ Mình có thể tư duy ra sơ đồ này bằng việc đọc tên file là `wsgi_app.py` và trong file cấu hình docker có sử dụng cả python flask và apache → dựa vào kinh nghiệm cá nhân đã triển khai 1 web server để biết (hoặc chưa triển khai bao giờ thì research trên mạng).

**Tiếp theo là file `httpd-append.conf`** 

Đây là file Config của server Apache. tại sao lại là [httpd](https://www.notion.so/Writeups-TAMU-CTF-2026-32bb8a8ee38b8015bfa3f9e38ceb9d03?pvs=21)? tại tên nó thế đi 😉. Khi đọc thông tin cấu hình từ file này mình biết được 3 thông tin quan trọng sau:

Thứ nhất là:

```bash
WSGIScriptAlias / /srv/app/wsgi_app.py
```

Cú pháp: `WSGIScriptAlias [URL] [file vật lý]`

- `ScriptAlias` là lệnh, dùng để nói: *"Khi có request vào URL này, đừng trả file tĩnh không, hãy chạy file đó trước, như một script và trả về kết quả sau đó"*
- `/` → URL path: tức là **mọi request** vào website
    - Ví dụ với URL Web: [https://bad-apple.tamuctf.com/](https://bad-apple.tamuctf.com/), dấu `/` sau `.com` có thể hiểu là bạn yêu cầu máy chủ Apache trả về tài nguyên - kết quả xử lý của `wsgi_app.py` về cho bạn.
- `wsgi_app.py` nằm ở `/srv/app/wsgi_app.py` → File Python này sẽ xử lý request đó

Thứ 2 là:

```bash
Alias /browse /srv/http/uploads
```

Tạo một **shortcut URL** — ánh xạ URL sang thư mục vật lý trên máy chủ.

Ví dụ:

- **Người dùng vào:**   [https://bad-apple.tamuctf.com/](https://bad-apple.tamuctf.com/)browse
- **Apache hiểu là:**    [https://bad-apple.tamuctf.com](https://bad-apple.tamuctf.com/)/srv/http/uploads  (thư mục thật trên server)

```bash
Options +Indexes
```

Đây là một cấu hình quan trọng cho phép Apache **hiển thị danh sách file** trong thư mục khi không có `index.html`.

Nếu:

- Không có `Options +Indexes`  →  403 Forbidden (Không tìm thấy)
- Có `Options +Indexes`        →  Hiện danh sách file

→ Damn, vậy là mình có thể xem file trong thư mục `/srv/http/uploads` bằng cách thêm `/browse` vào URL? thử xem sao.

![image.png](/assets/img/ctf/tamu-ctf-2026/image%203.png)

Liên kết với chi tiết khi mình đọc file Docker ở chỗ [này](https://www.notion.so/Writeups-TAMU-CTF-2026-32bb8a8ee38b8015bfa3f9e38ceb9d03?pvs=21), mình thử tìm mục admin và truy cập vào.

![image.png](/assets/img/ctf/tamu-ctf-2026/image%204.png)

Yes, có vẻ mình đã tìm được file Flag mà mình [nghi ngờ](https://www.notion.so/Writeups-TAMU-CTF-2026-32bb8a8ee38b8015bfa3f9e38ceb9d03?pvs=21) lúc trước, nó là 1 file GIF.

```python
e017b6321bda6812ec80e9fac368709e-flag.gif
```

Nhưng khi mở ra xem thử thì chuyện này xảy ra:

![image.png](/assets/img/ctf/tamu-ctf-2026/image%205.png)

File này cần thông tin tài khoản, mật khẩu để mở ??? Điều này dẫn tới sự thật phũ phàng thứ 3 mà mình đọc được từ file cấu hình:

Thứ 3 là:

```bash
<FilesMatch "\.gif$">
	AuthType Basic
	AuthName "Admin Area"
	AuthUserFile /srv/http/.htpasswd
	Require valid-user
</FilesMatch>
```

Để xem mọi file có đuôi .gif `<FilesMatch "\.gif$">` hệ thống sẽ yêu cầu tên tài khoản là "Admin Area" và một mật khẩu là cái gì đó nằm trong file [“.htpasswd”](https://www.notion.so/Writeups-TAMU-CTF-2026-32bb8a8ee38b8015bfa3f9e38ceb9d03?pvs=21)

→ Mình không có bất kỳ manh mối nào để vào được thư mục `/srv/http/.htpasswd` nơi duy nhất mà mình vào được là thư mục [upload](https://www.notion.so/Writeups-TAMU-CTF-2026-32bb8a8ee38b8015bfa3f9e38ceb9d03?pvs=21), vậy phải có một cách nào đấy để bypass cái xác thực này và đọc được nội dung file GIF kia!!!

**Cuối cùng là file `wsgi_app.py`** 

Đây chính là file xử lý [logic của trang web này](https://www.notion.so/Writeups-TAMU-CTF-2026-32bb8a8ee38b8015bfa3f9e38ceb9d03?pvs=21): *GIF/Video → ffmpeg xử lý file GIF/Video → Thành các Frame ảnh → Trả về* frontend → Frontend dùng JavaScript để render từng frame thành video ASCII Art

**Bình tĩnh, muốn hiểu thì mình phải giải thích chút về code web của python đã:**

`@app.route('/')` là một [decorator](https://viblo.asia/p/function-decorator-trong-python-gDVK2QDe5Lj) trong Flask dùng để **ánh xạ một URL tới một hàm xử lý.**

Bạn có thể đọc thêm về decorator, nhưng để dễ hiểu thì như này:

- Khi bạn gõ URL, ví dụ như `/upload` ([https://bad-apple.tamuctf.com/](https://bad-apple.tamuctf.com/convert)upload) vào trình duyệt
- Apache sẽ ánh xạ URL đó và thư mục thực tế trên server qua cấu hình apache [này.](https://www.notion.so/Writeups-TAMU-CTF-2026-32bb8a8ee38b8015bfa3f9e38ceb9d03?pvs=21)
- Flask sẽ nhận được yêu cầu, tìm route tương ứng ở trong code python đó
- Gọi hàm Python được gán cho route đó (`def upload()`)
- Xử lý
- Trả về response.

![image.png](/assets/img/ctf/tamu-ctf-2026/image%206.png)

Một cái cần biết nữa trong code Python đó là `methods=['POST']` nằm ngay đằng sau.upload Thấy ko?

Cái này là gì? Nó chỉ định HTTP method được chấp nhận. nếu không khai báo thì mặc định chỉ có `GET` .

Ở đây có `POST` tức là cả `POST` và `GET` là hai Methods được chấp nhận

→ Mà tại sao lại có `POST`? `POST` có nghĩa là Flask chấp nhận bạn tải cái gì đó lên server (route tên là /upload mà bro!)

→ `GET` thì Flask chỉ cho bạn kết quả trả về thôi!

**OK giải thích vậy đủ rồi, đi săn lỗi nào!!**

Trong code python này có 4 route

- `@app.route('/')` Trả về cái giao diện web đó.
- `@app.route('/upload', methods=['POST'])` Xử lý dữ liệu video/gif mà bạn upload lên.
- `@app.route('/convert')` Extract frames từ file đã upload → redirect về `/`
- `@app.route('/get_frames')` Trả về dữ liệu JSON cho Frontend

Và hai biến thư mục ở dòng 11,12:

```python
UPLOAD_FOLDER = '/srv/http/uploads'
FRAMES_BASE = '/srv/http/static/frames'
```

Ma xui quỷ khiến mình check `/convert` trước

```python
@app.route('/convert')
def convert():
    user_id = request.args.get('user_id', 'anonymous')
    filename = request.args.get('filename', '')

    input_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(user_id), filename)
    if not os.path.exists(input_path):
        return "File not found", 404

    safe_name = os.path.splitext(os.path.basename(filename))[0]
    output_dir = os.path.join(FRAMES_BASE, user_id, safe_name)
    os.makedirs(output_dir, exist_ok=True)

    try:
        frame_count = extract_frames(input_path, output_dir, safe_name)
        return redirect(url_for('index', view=safe_name, user_id=user_id))
    except Exception as e:
        return f"Error processing file: {str(e)}", 500
```

Đầu tiên là hai dòng này

```python
user_id = request.args.get('user_id', 'anonymous')
gif_name = request.args.get('gif_name', '')
```

ta thấy hai biến `user_id` và `gif_name` sẽ được gán cho một giá trị thông qua hàm request.args.get()

→ Hàm này sẽ lấy từ chính URL của mình nhập vào

 → để hiểu theo cách đơn giản, hay làm như này

thử gõ vào thanh tìm kiếm: [https://bad-apple.tamuctf.com/convert](https://bad-apple.tamuctf.com/convert)

nó sẽ redirect bạn vào một đường dẫn URL như này: 

![image.png](/assets/img/ctf/tamu-ctf-2026/image%207.png)

Vì mình không truyền tham số query vào cho URL nó sẽ trả về mặc định là:

`user_id = request.args.get('user_id', 'anonymous')` → mặc định là ‘anonymous’

`filename = request.args.get('filename', '')` → mặc định là không có gì ‘ ‘

Ok, tiếp theo là dòng code này:

```python
input_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(user_id), filename)
```

Vì hàm convert là hàm dùng để chuyển đổi từ video/GIF → picture frame, nó phải có đường dẫn tới file đầu vào và đường dẫn tới file đầu ra

vậy cùng xem đường dẫn này được ghép như nào nhé:

- `app.config['UPLOAD_FOLDER']` đây là đường dẫn tới file upload với biến [UPLOAD_FOLDER](https://www.notion.so/Writeups-TAMU-CTF-2026-32bb8a8ee38b8015bfa3f9e38ceb9d03?pvs=21) đã nhắc tới ở trên → chính là đường dẫn thực tế trên hệ thống, [nơi lưu file flag](https://www.notion.so/Writeups-TAMU-CTF-2026-32bb8a8ee38b8015bfa3f9e38ceb9d03?pvs=21)
- `secure_filename(user_id)` đây chính là biến [user_id](https://www.notion.so/Writeups-TAMU-CTF-2026-32bb8a8ee38b8015bfa3f9e38ceb9d03?pvs=21) ta truyền vào ở trên
- `filename` là file video/gif ta muốn convert

Lỗi chí mạng ở đây: nếu mình truyền vào:

`user_id = admin` và `filename = [e017b6321bda6812ec80e9fac368709e-flag.gif](https://www.notion.so/Writeups-TAMU-CTF-2026-32bb8a8ee38b8015bfa3f9e38ceb9d03?pvs=21)` 

Ta sẽ có đường dẫn Input là:

`/srv/http/uploads/admin/e017b6321bda6812ec80e9fac368709e-flag.gif` 

Trỏ trực tiếp tới file cờ tôi đang muốn đọc

Hàm convert sẽ đọc file cờ này, extract nó ra thành từng frame và lưu vào FRAMES_BASE qua dòng code này:

```python
output_dir = os.path.join(FRAMES_BASE, user_id, safe_name)
```

Tức là ở vị trí đường dẫn:

`/srv/http/[static/frames/admin/](https://bad-apple.tamuctf.com/static/frames/admin/318c8a8e8d58ce1a13309dada5be99e7-flag/frame_$%7Bi%7D.png)e017b6321bda6812ec80e9fac368709e-flag/` 

tại đây, nó sẽ lưu từng frame 1 của file GIF cờ kia.

Như ý trời đã định `/srv/http/[static/frames/admin/](https://bad-apple.tamuctf.com/static/frames/admin/318c8a8e8d58ce1a13309dada5be99e7-flag/frame_$%7Bi%7D.png)e017b6321bda6812ec80e9fac368709e-flag/` là tệp con của tệp `/srv/http/[static/](https://bad-apple.tamuctf.com/static/frames/admin/318c8a8e8d58ce1a13309dada5be99e7-flag/frame_$%7Bi%7D.png)` . Mà tệp này được server public luôn với mục đích gửi các frame này về cho Frontend (Dòng 9).

```python
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'),  static_folder='/srv/http/static')
```

**Ok, lại rất nhiều giải thích r, giờ là lúc mình đi vào thực hành:**

dùng lệnh `curl` để chủ động tương tác với route `/convert` :

```python
curl -v "https://bad-apple.tamuctf.com/convert?user_id=admin&filename=e017b6321bda6812ec80e9fac368709e-flag.gif"
```

kết quả trả về 302, tức là ta đã thành công convert file flag, ta sẽ dùng `curl` để lấy frame đầu tiên về

```python
curl -s "https://bad-apple.tamuctf.com/static/frames/admin/e017b6321bda6812ec80e9fac368709e-flag/frame_0001.png" -o frame_0001.png
```

có luôn frame đầu tiên:

![frame_0001.png](/assets/img/ctf/tamu-ctf-2026/frame_0001.png)

giờ tôi sẽ dùng `curl` để lấy 200 frame đầu tiên đi

```python
mkdir flag_frames && cd flag_frames
for i in $(seq -f "%04g" 1 200); do
    curl -s "https://bad-apple.tamuctf.com/static/frames/admin/e017b6321bda6812ec80e9fac368709e-flag/frame_${i}.png" -o "frame_${i}.png"
done
```

![image.png](/assets/img/ctf/tamu-ctf-2026/image%208.png)

OK luôn!

Flag: gigem{3z_t0uh0u_fl4g_r1t3}

# II. Forensics

![image.png](/assets/img/ctf/tamu-ctf-2026/image%209.png)

Bài cho mình một file memory dump và một file encrypt bằng AES CBC. Mục tiêu là tìm khóa để giải mã file encrypt nằm bên trong file `.dump` kia.

Vì đây là file memory dump, ta có thể sử dụng Volatility3.

 

![image.png](/assets/img/ctf/tamu-ctf-2026/image%2010.png)

# III. Misc

![image.png](/assets/img/ctf/tamu-ctf-2026/image%2011.png)

![image.png](/assets/img/ctf/tamu-ctf-2026/image%2012.png)

![image.png](/assets/img/ctf/tamu-ctf-2026/image%2013.png)

![image.png](/assets/img/ctf/tamu-ctf-2026/image%2014.png)

![image.png](/assets/img/ctf/tamu-ctf-2026/image%2015.png)