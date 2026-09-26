# BÁO CÁO: MÃ HÓA ĐỐI XỨNG (DES/AES) VÀ MÃ HÓA BẤT ĐỐI XỨNG (RSA)

**Môn học:** An toàn và bảo mật thông tin

---

## PHẦN 1: THUẬT TOÁN MÃ HÓA HIỆN ĐẠI — DES VÀ AES

### 1.1. Thuật toán DES (Data Encryption Standard)

**Tổng quan**

| Thuộc tính | Giá trị |
|---|---|
| Loại | Mã hóa khối, đối xứng |
| Kích thước khối | 64 bit |
| Kích thước khóa | 64 bit (56 bit thực dùng + 8 bit kiểm tra chẵn lẻ) |
| Số vòng lặp | 16 vòng |
| Cấu trúc | Mạng Feistel (Feistel Network) |
| Năm ban hành | 1977 (NIST/NBS) |

**Nguyên lý cấu trúc Feistel**

DES chia khối bản rõ 64 bit thành 2 nửa trái/phải (L, R) mỗi nửa 32 bit, sau đó lặp qua 16 vòng biến đổi giống nhau, mỗi vòng dùng một khóa con (subkey) 48 bit sinh ra từ khóa chính.

**Quy trình mã hóa DES**

1. **Hoán vị khởi tạo (IP – Initial Permutation):** Sắp xếp lại 64 bit bản rõ theo bảng hoán vị cố định.
2. **16 vòng Feistel:** Với mỗi vòng i = 1..16:
   - `L(i) = R(i-1)`
   - `R(i) = L(i-1) XOR f(R(i-1), K(i))`
   - Hàm `f` gồm: mở rộng E (32→48 bit) → XOR với khóa con K(i) → thay thế qua 8 hộp S-box (48→32 bit) → hoán vị P.
3. **Đảo 2 nửa** sau vòng 16 (swap L và R).
4. **Hoán vị kết thúc (IP⁻¹):** Nghịch đảo của IP, cho ra bản mã 64 bit.

**Sinh khóa con:** Khóa 64 bit → loại bỏ 8 bit chẵn lẻ (còn 56 bit) → hoán vị PC-1 → chia 2 nửa 28 bit → dịch trái vòng theo lịch trình → hoán vị nén PC-2 (56→48 bit) tạo K(i) cho từng vòng.

**Quy trình giải mã:** Giống hệt quy trình mã hóa nhưng dùng thứ tự khóa con **ngược lại** (K16, K15, ..., K1), nhờ tính đối xứng của cấu trúc Feistel.

**Hạn chế của DES:** Khóa 56 bit quá ngắn, dễ bị tấn công vét cạn (brute-force) với máy tính hiện đại (đã bị phá trong vài giờ từ cuối thập niên 1990) → dẫn đến việc dùng **3DES** (áp dụng DES 3 lần với 2 hoặc 3 khóa khác nhau) và sau đó bị thay thế hoàn toàn bởi **AES**.

---

### 1.2. Thuật toán AES (Advanced Encryption Standard)

**Tổng quan**

| Thuộc tính | Giá trị |
|---|---|
| Loại | Mã hóa khối, đối xứng |
| Kích thước khối | 128 bit (cố định) |
| Kích thước khóa | 128 / 192 / 256 bit |
| Số vòng | 10 (128-bit key) / 12 (192-bit) / 14 (256-bit) |
| Cấu trúc | Mạng thay thế – hoán vị (SPN – Substitution-Permutation Network) |
| Năm chuẩn hóa | 2001 (NIST, thay thế DES) |
| Thuật toán gốc | Rijndael (Joan Daemen & Vincent Rijmen) |

Dữ liệu được biểu diễn dưới dạng **ma trận trạng thái (state)** 4×4 byte (16 byte = 128 bit).

**Các phép biến đổi chính trong mỗi vòng**

1. **SubBytes:** Thay thế từng byte của state bằng giá trị tương ứng trong hộp thế S-box (dựa trên nghịch đảo trong trường hữu hạn GF(2⁸) kết hợp biến đổi affine) → tạo tính phi tuyến, chống phân tích tuyến tính/vi phân.
2. **ShiftRows:** Dịch vòng trái các hàng của ma trận trạng thái: hàng 0 không dịch, hàng 1 dịch 1 byte, hàng 2 dịch 2 byte, hàng 3 dịch 3 byte → khuếch tán dữ liệu theo chiều ngang.
3. **MixColumns:** Nhân mỗi cột (4 byte) với một ma trận cố định trong GF(2⁸) → khuếch tán dữ liệu theo chiều dọc (bỏ qua ở vòng cuối cùng).
4. **AddRoundKey:** XOR state với khóa con của vòng hiện tại (round key), sinh ra từ thuật toán **Key Expansion** (mở rộng khóa gốc thành các round key riêng cho từng vòng).

**Quy trình mã hóa AES (128-bit key, 10 vòng)**

```
1. AddRoundKey (với khóa gốc, vòng 0)
2. Lặp 9 vòng:
     SubBytes → ShiftRows → MixColumns → AddRoundKey
3. Vòng cuối (vòng 10, không có MixColumns):
     SubBytes → ShiftRows → AddRoundKey
```

**Quy trình giải mã AES:** Thực hiện các phép biến đổi **nghịch đảo** theo thứ tự ngược lại:

```
1. AddRoundKey (với round key cuối cùng)
2. Lặp 9 vòng:
     InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
3. Vòng cuối:
     InvShiftRows → InvSubBytes → AddRoundKey (với khóa gốc)
```

Trong đó InvSubBytes dùng S-box nghịch đảo, InvShiftRows dịch phải, InvMixColumns nhân với ma trận nghịch đảo.

**Các chế độ hoạt động (Mode of Operation) thường dùng cùng AES:** ECB (không nên dùng vì lộ mẫu dữ liệu), CBC (cần vector khởi tạo IV, chaining các khối), CTR, GCM (cung cấp cả tính bí mật và xác thực – Authenticated Encryption).

**So sánh nhanh DES vs AES**

| Tiêu chí | DES | AES |
|---|---|---|
| Kích thước khối | 64 bit | 128 bit |
| Độ dài khóa | 56 bit | 128/192/256 bit |
| Cấu trúc | Feistel | SPN |
| Độ an toàn hiện nay | Không an toàn | An toàn (chuẩn hiện hành) |
| Tốc độ | Chậm hơn (phần mềm) | Nhanh, tối ưu tốt cả phần cứng lẫn phần mềm |

---

### 1.3. Cài đặt AES bằng Python (dùng thư viện `pycryptodome`)

```python
"""
Cài đặt minh họa mã hóa/giải mã AES-256, chế độ CBC
Yêu cầu: pip install pycryptodome
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def aes_encrypt(plaintext: str, key: bytes) -> str:
    """Mã hóa chuỗi bản rõ bằng AES-CBC, trả về chuỗi base64 (IV + ciphertext)."""
    iv = get_random_bytes(16)                       # Vector khởi tạo ngẫu nhiên 16 byte
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    # Ghép IV vào trước bản mã để dùng khi giải mã
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(enc_b64: str, key: bytes) -> str:
    """Giải mã chuỗi base64 (IV + ciphertext) trả về bản rõ."""
    raw = base64.b64decode(enc_b64)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_data, AES.block_size)
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    key = get_random_bytes(32)          # Khóa 256 bit (AES-256)
    message = "An toan va bao mat thong tin - AES demo"

    encrypted = aes_encrypt(message, key)
    print("Ban ma (base64):", encrypted)

    decrypted = aes_decrypt(encrypted, key)
    print("Ban ro sau giai ma:", decrypted)
```

**Giải thích:**
- `AES.new(key, AES.MODE_CBC, iv)`: khởi tạo bộ mã hóa với khóa và IV, chế độ CBC.
- `pad`/`unpad`: đệm dữ liệu cho đủ bội số 16 byte (kích thước khối AES) theo chuẩn PKCS#7.
- IV được sinh ngẫu nhiên cho mỗi lần mã hóa và gửi kèm bản mã (không cần giữ bí mật IV, chỉ cần khóa `key` là bí mật).

---

## PHẦN 2: THUẬT TOÁN MÃ HÓA BẤT ĐỐI XỨNG RSA

### 2.1. Giới thiệu

RSA (Rivest–Shamir–Adleman, 1977) là thuật toán mã hóa **bất đối xứng (khóa công khai)** đầu tiên được sử dụng rộng rãi, dựa trên độ khó của bài toán **phân tích một số nguyên lớn thành thừa số nguyên tố**.

Khác với AES/DES (1 khóa dùng chung cho cả 2 bên), RSA dùng **cặp khóa**:
- **Khóa công khai (Public Key)** – công bố rộng rãi, dùng để mã hóa hoặc xác minh chữ ký.
- **Khóa bí mật (Private Key)** – giữ riêng, dùng để giải mã hoặc tạo chữ ký.

### 2.2. Nguyên lý sinh cặp khóa RSA

**Các bước sinh khóa:**

1. **Chọn 2 số nguyên tố lớn** `p` và `q` (ngẫu nhiên, độc lập, thường mỗi số ≥ 1024 bit đối với khóa 2048 bit).
2. **Tính modulus:** `n = p × q`. Giá trị `n` được dùng trong cả khóa công khai lẫn bí mật; độ dài bit của `n` là "độ dài khóa RSA" (vd RSA-2048).
3. **Tính hàm Euler:** `φ(n) = (p-1) × (q-1)`.
4. **Chọn số mũ công khai `e`:** thỏa `1 < e < φ(n)` và `gcd(e, φ(n)) = 1` (e và φ(n) nguyên tố cùng nhau). Thường chọn `e = 65537` vì tính toán nhanh và an toàn.
5. **Tính số mũ bí mật `d`:** là nghịch đảo modulo của `e` theo `φ(n)`, tức là:
   `d × e ≡ 1 (mod φ(n))`
   (tính bằng thuật toán Euclid mở rộng).
6. **Kết quả:**
   - Khóa công khai: `(e, n)`
   - Khóa bí mật: `(d, n)`
   - `p, q, φ(n)` phải được **hủy bỏ** sau khi sinh khóa xong (không được lưu lại).

**Công thức mã hóa/giải mã:**

- Mã hóa: `C = M^e mod n`
- Giải mã: `M = C^d mod n`

**Vì sao an toàn:** Để tính được `d` từ khóa công khai `(e, n)`, kẻ tấn công cần tính `φ(n)`, điều này đòi hỏi phải **phân tích `n` ra thừa số nguyên tố `p, q`** — bài toán được xem là "khó" về mặt tính toán khi `n` đủ lớn (2048–4096 bit).

**Ví dụ minh họa với số nhỏ:**
- Chọn p = 61, q = 53 → n = 3233, φ(n) = 60×52 = 3120
- Chọn e = 17 (nguyên tố cùng nhau với 3120)
- Tính d: 17 × d ≡ 1 (mod 3120) → d = 2753
- Khóa công khai: (17, 3233); Khóa bí mật: (2753, 3233)
- Mã hóa M = 65: C = 65^17 mod 3233 = 2790
- Giải mã: M = 2790^2753 mod 3233 = 65 ✓

---

## PHẦN 3: CÁC MÔ HÌNH ÁP DỤNG RSA VÀ SO SÁNH VỚI AES

### 3.1. Mô hình xác thực người nhận (đảm bảo tính bí mật)

**Mục tiêu:** Chỉ người nhận hợp lệ mới đọc được thông điệp.

**Quy trình:**
1. Người gửi lấy **khóa công khai của người nhận**.
2. Mã hóa thông điệp: `C = M^(e_nhận) mod n`.
3. Gửi `C` đi.
4. Người nhận dùng **khóa bí mật của chính mình** để giải mã: `M = C^(d_nhận) mod n`.

→ Vì chỉ người nhận giữ khóa bí mật tương ứng, chỉ họ mới giải mã được. Mô hình này đảm bảo **tính bí mật (confidentiality)**, không đảm bảo ai là người gửi.

### 3.2. Mô hình xác thực người gửi (chữ ký số)

**Mục tiêu:** Người nhận xác nhận đúng thông điệp đến từ người gửi xác định (không bị giả mạo) và không bị chối bỏ (non-repudiation).

**Quy trình:**
1. Người gửi "mã hóa" (thực chất là **ký**) bằng **khóa bí mật của mình**: `S = M^(d_gửi) mod n` (thường ký trên giá trị băm/hash của M, không ký trực tiếp toàn bộ thông điệp để tăng tốc).
2. Gửi `(M, S)`.
3. Người nhận dùng **khóa công khai của người gửi** để kiểm tra: `M' = S^(e_gửi) mod n`, so sánh `M'` với `M` (hoặc hash tương ứng).

→ Vì chỉ người gửi có khóa bí mật, chữ ký chỉ có thể tạo bởi người gửi → xác thực nguồn gốc. Mô hình này **không đảm bảo bí mật** (ai cũng dùng khóa công khai đọc lại được `M`).

### 3.3. Mô hình kết hợp cả hai (bí mật + xác thực)

**Mục tiêu:** Vừa đảm bảo chỉ người nhận đọc được, vừa xác thực đúng người gửi.

**Quy trình (ký trước, mã hóa sau – phổ biến nhất):**
1. Người gửi ký thông điệp bằng khóa bí mật của mình: `S = Hash(M)^(d_gửi) mod n`.
2. Mã hóa cả `(M, S)` bằng khóa công khai của người nhận: `C = (M, S)^(e_nhận) mod n`.
3. Gửi `C`.
4. Người nhận giải mã bằng khóa bí mật của mình để lấy lại `(M, S)`.
5. Người nhận dùng khóa công khai của người gửi để xác minh chữ ký `S`.

→ Đạt cả 2 mục tiêu: **bảo mật** (chỉ người nhận giải mã được) và **xác thực + toàn vẹn + chống chối bỏ** (chỉ người gửi tạo được chữ ký hợp lệ).

### 3.4. So sánh thời gian mã hóa/giải mã RSA và AES

| Tiêu chí | AES (đối xứng) | RSA (bất đối xứng) |
|---|---|---|
| Tốc độ mã hóa/giải mã | Rất nhanh (dùng phép XOR, hoán vị, thay thế đơn giản trên phần cứng/phần mềm) | Chậm hơn nhiều (phải tính lũy thừa modulo số rất lớn) |
| Độ phức tạp tính toán | O(n) theo kích thước dữ liệu, chi phí thấp cho mỗi khối | Chi phí cao vì số mũ và modulus có hàng trăm/nghìn bit |
| Khả năng xử lý dữ liệu lớn | Rất phù hợp (mã hóa file, luồng dữ liệu lớn) | Không phù hợp cho dữ liệu lớn — thường giới hạn kích thước bản rõ nhỏ hơn kích thước khóa |
| Độ dài khóa để đạt cùng mức an toàn | 128 bit AES ≈ tương đương RSA 3072 bit | Cần khóa dài hơn nhiều lần để đạt độ an toàn tương đương |
| Ước lượng tốc độ tương đối | Nhanh hơn RSA khoảng **100–1000 lần** tùy cài đặt và kích thước khóa | Chậm hơn AES đáng kể, đặc biệt ở thao tác giải mã (dùng số mũ bí mật lớn) |
| Vấn đề quản lý khóa | Cần trao đổi khóa bí mật an toàn trước (bài toán phân phối khóa) | Không cần trao đổi khóa bí mật trước — chỉ cần công bố khóa công khai |

**Nhận xét:** RSA an toàn về mặt trao đổi khóa nhưng tốc độ xử lý kém hơn AES rất nhiều khi dữ liệu lớn. Ngược lại AES rất nhanh nhưng gặp khó khăn trong việc phân phối khóa bí mật an toàn giữa 2 bên khi chưa có kênh an toàn từ trước.

### 3.5. Giải pháp kết hợp sức mạnh của RSA và AES (Hybrid Cryptosystem)

Đây chính là mô hình được dùng thực tế trong hầu hết các hệ thống bảo mật hiện nay (TLS/HTTPS, PGP/GPG, mã hóa email, VPN...).

**Ý tưởng:** Dùng RSA để giải quyết bài toán trao đổi khóa an toàn, dùng AES để mã hóa dữ liệu thực với tốc độ cao.

**Quy trình mã hóa lai (Hybrid Encryption):**

1. Bên gửi tạo ngẫu nhiên một **khóa phiên (session key)** đối xứng, dùng cho AES (ví dụ khóa AES-256).
2. Dùng **AES** với khóa phiên này để mã hóa toàn bộ dữ liệu/thông điệp thực sự (nhanh, hiệu quả với dữ liệu lớn).
3. Dùng **RSA** với khóa công khai của bên nhận để mã hóa **khóa phiên AES** (dữ liệu rất nhỏ, chỉ 16–32 byte, nên RSA xử lý nhanh dù chậm hơn AES).
4. Gửi đi gói tin gồm: `[Khóa phiên đã mã hóa bằng RSA] + [Dữ liệu đã mã hóa bằng AES]`.
5. Bên nhận:
   - Dùng **khóa bí mật RSA** của mình giải mã để lấy lại khóa phiên AES.
   - Dùng khóa phiên AES vừa khôi phục để giải mã dữ liệu chính.

**Sơ đồ tổng quát:**

```
Bên gửi:
  session_key = random_AES_key()
  encrypted_data = AES_Encrypt(data, session_key)
  encrypted_key  = RSA_Encrypt(session_key, RSA_public_key_of_receiver)
  gửi (encrypted_key, encrypted_data)

Bên nhận:
  session_key = RSA_Decrypt(encrypted_key, RSA_private_key_of_receiver)
  data = AES_Decrypt(encrypted_data, session_key)
```

**Ưu điểm của mô hình lai:**
- Tận dụng **tốc độ cao của AES** cho khối lượng dữ liệu lớn.
- Tận dụng **khả năng trao đổi khóa an toàn không cần kênh bí mật trước** của RSA.
- Có thể kết hợp thêm **chữ ký số RSA** (ký hash của dữ liệu) để đồng thời đạt được xác thực nguồn gốc, toàn vẹn dữ liệu và chống chối bỏ, bên cạnh tính bí mật.

**Ứng dụng thực tế của mô hình lai:**
- **TLS/SSL (HTTPS):** dùng RSA (hoặc ECDHE) để trao đổi khóa phiên, sau đó dùng AES-GCM để mã hóa toàn bộ phiên làm việc.
- **PGP/GPG (mã hóa email):** mã hóa nội dung email bằng AES, mã hóa khóa AES bằng RSA của người nhận, kèm chữ ký RSA của người gửi.
- **VPN, SSH:** giai đoạn bắt tay (handshake) dùng mã hóa bất đối xứng để thống nhất khóa phiên, sau đó dùng mã hóa đối xứng cho toàn bộ dữ liệu truyền.

---

## KẾT LUẬN

- **DES** có kích thước khóa quá ngắn (56 bit), không còn an toàn trong thực tế và đã được thay thế bởi **AES**, sử dụng cấu trúc SPN với khóa 128/192/256 bit, hiệu năng cao và độ an toàn được công nhận rộng rãi.
- **RSA** giải quyết bài toán phân phối khóa bằng cách dùng cặp khóa công khai/bí mật dựa trên độ khó phân tích thừa số nguyên tố, nhưng có tốc độ xử lý chậm hơn nhiều so với AES.
- Trong thực tế, các hệ thống bảo mật hiện đại luôn **kết hợp RSA (hoặc các thuật toán bất đối xứng khác) với AES** thành mô hình mã hóa lai (hybrid), khai thác đồng thời ưu điểm của cả 2: tốc độ của mã hóa đối xứng và khả năng trao đổi khóa an toàn của mã hóa bất đối xứng, đồng thời có thể bổ sung chữ ký số để đảm bảo xác thực và toàn vẹn dữ liệu.
