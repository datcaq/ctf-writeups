# Capture The Flag — Write-ups

Tổng hợp write-up và script tái hiện kết quả từ các thử thách CTF đã thực hiện. Mỗi bài ghi lại cách phân tích dữ liệu, kiểm chứng giả thuyết và rút ra bài học từ quá trình giải.

## Danh sách bài

| Giải | Thể loại | Challenge | Kỹ thuật chính | Write-up |
|---|---|---|---|---|
| CSCV2026 | Misc | **Weirdo** | PCAP · MAVLink · CRC · GPS visualization | [Đọc bài](CSCV2026/misc/weirdo/) |
| CSCV2026 | Crypto | **Typhone** | LCG · RSA · GCM nonce reuse · ECDSA · Lattice attacks | [Đọc bài](CSCV2026/crypto/typhone/) |

## Bài nổi bật: Weirdo

Dựng lại chữ ẩn trong quỹ đạo drone từ 3.302 bản tin MAVLink có checksum hợp lệ. Bài viết trình bày cả nhánh flag mồi và cách chuyển sang phân tích tọa độ GPS.

[![Chữ ẩn trong quỹ đạo GPS của bài Weirdo](CSCV2026/misc/weirdo/images/gps-flag.png)](CSCV2026/misc/weirdo/)

## Cấu trúc

```text
<event>/<category>/<challenge>/
├── README.md          # Phân tích và kết quả
├── solve.py           # Script tái hiện
├── requirements.txt   # Thư viện cần thiết
└── images/            # Hình minh họa và bằng chứng
```

Hướng dẫn chạy, nguồn dữ liệu và ghi nhận hỗ trợ được ghi riêng trong từng bài. Các write-up có tiết lộ lời giải và flag.
