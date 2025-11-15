# Hướng Dẫn Nhanh - Hệ Thống Phát Hiện Lừa Đảo
# Quick Start Guide - Phishing & Malware Detection System

> **Ngôn ngữ / Language**: [Tiếng Việt](#vietnamese) | [English](#english)

---

<a name="vietnamese"></a>
## 🇻🇳 PHIÊN BẢN TIẾNG VIỆT

## 🚀 Bắt Đầu Trong 5 Phút

### Bước 1: Cài Đặt Dependencies (1 phút)
```bash
# Kích hoạt môi trường ảo
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Cài đặt packages
pip install -r config/requirements.txt
```

### Bước 2: Kiểm Tra Cài Đặt (30 giây)
```bash
python check_system.py
```
✅ Sẽ hiển thị: "All systems operational!"

### Bước 3: Khởi Chạy Ứng Dụng (10 giây)

#### GUI Desktop (Khuyến nghị)
```bash
python main.py desktop
```
- Không hiển thị cửa sổ console
- Giao diện theme tối
- Nhấn "📧 Email Detector" hoặc "🔒 File Analyzer"

#### Giao Diện Web
```bash
python main.py web
```
- Mở trình duyệt: http://localhost:5000
- Nhấn "Check Email" hoặc "Scan File"

---

## 📧 Test Phát Hiện Email

### Ví Dụ 1: Email Lừa Đảo
```
Dán vào Email Detector:

From: admin@paypa1.com
Subject: Khẩn cấp: Cần xác minh tài khoản

Tài khoản của bạn sẽ bị đình chỉ!
Nhấn vào đây ngay lập tức: http://bit.ly/verify123
```

**Kết Quả Mong Đợi:**
- 🚨 ĐÃ PHÁT HIỆN LỪA ĐẢO
- Rủi ro: High - Critical (Cao - Nghiêm trọng)
- Độ tin cậy: 70-95%
- Lý do: URL rút gọn (bit.ly), từ khóa đáng ngờ, tên miền giả mạo

### Ví Dụ 2: Email Hợp Lệ
```
Dán vào:

From: github@github.com
Subject: Tổng hợp hàng tuần của bạn

Đây là các repository thịnh hành tuần này:
- awesome-python
- tensorflow
```

**Kết Quả Mong Đợi:**
- ✅ EMAIL HỢP LỆ hoặc ⚠️ UNCERTAIN
- Rủi ro: Safe (70%+) hoặc Uncertain (<50%)
- Độ tin cậy: Tùy thuộc vào đặc trưng email
- Lưu ý: Nếu độ tin cậy < 50%, hệ thống sẽ hiển thị "Uncertain" thay vì "Legitimate"

---

## 🔒 Test Phân Tích File

### Test Nhanh
```bash
# Tạo file test
echo "MZ test content" > test.exe

# Phân tích qua desktop app
1. Nhấn "📁 Browse..."
2. Chọn test.exe
3. Nhấn "🔍 Phân Tích File"
```

---

## 🎓 Training Model Tùy Chỉnh

### Sử Dụng Desktop App
1. Vào tab "🎓 Train Model"
2. Chọn loại model: Email hoặc File
3. Nhấn "📁 Chọn File Dữ Liệu Training"
4. Chọn file CSV từ `data/training_samples/`
5. Nhấn "🚀 Bắt Đầu Training"

### Sử Dụng Command Line
```bash
python dev/scripts/train_pretrained.py
```

---

## 🔧 Lệnh Thường Dùng

```bash
# Ứng dụng desktop
python main.py desktop

# Web server
python main.py web

# Kiểm tra hệ thống
python check_system.py

# Chạy tests
python dev/tests/test_suite.py

# Training models
python dev/scripts/train_pretrained.py
```

---

## 💡 Mẹo Sử Dụng

### Phân Tích Nhanh Hơn
- Kết quả được cache tự động
- Phân tích lần thứ 2 của cùng nội dung sẽ tức thì
- Xóa cache trong tab Settings nếu cần

### Độ Chính Xác Cao Hơn
- Bao gồm đầy đủ email headers (From, SPF, DKIM, DMARC)
- Cung cấp toàn bộ nội dung email (Subject + Body)
- Sử dụng đường dẫn file đầy đủ
- Giữ models được cập nhật

### Hiểu Kết Quả Phân Tích
**Risk Levels (Cấp Độ Rủi Ro):**
- `Safe`: Độ tin cậy ≥ 70% - Email rất có khả năng hợp lệ
- `Low Risk`: Độ tin cậy 50-70% - Khá an toàn nhưng cần cẩn thận
- `Uncertain`: Độ tin cậy < 50% - Không chắc chắn, cần kiểm tra thủ công
- `Low/Medium`: Phishing với độ tin cậy thấp-trung bình (40-60%)
- `High`: Phishing với độ tin cậy cao (60-80%)
- `Critical`: Phishing với độ tin cậy rất cao (≥80%)

**Lưu ý quan trọng:**
- Kết quả "Uncertain" không có nghĩa là email an toàn - chỉ là hệ thống không chắc chắn
- Luôn kiểm tra thủ công với emails có độ tin cậy < 70%
- Các yếu tố tăng nguy cơ: URL rút gọn, IP URLs, từ khóa khẩn cấp, yêu cầu thông tin

### Khắc Phục Sự Cố
```bash
# Sửa dependencies thiếu
pip install -r config/requirements.txt

# Sửa dữ liệu NLTK
python -c "import nltk; nltk.download('punkt_tab'); nltk.download('stopwords')"

# Reset mọi thứ
python check_system.py
```

---

## 📚 Bước Tiếp Theo

1. Đọc tài liệu đầy đủ: `HUONG_DAN.md`
2. Khám phá mẫu training: `data/training_samples/`
3. Kiểm tra báo cáo tối ưu: `OPTIMIZATION_REPORT.md`
4. Chạy test suite: `python dev/tests/test_suite.py`

---

**Cần Trợ Giúp?**
- Xem `HUONG_DAN.md` cho tài liệu chi tiết
- Chạy `python check_system.py` để chẩn đoán
- Xem lại `OPTIMIZATION_REPORT.md` cho thông tin hệ thống

**Liên Kết Nhanh:**
- Desktop App: `python main.py desktop`
- Web App: `python main.py web` → http://localhost:5000
- Tests: `python dev/tests/test_suite.py`

---

<a name="english"></a>
## 🇬🇧 ENGLISH VERSION

## 🚀 Quick Start (5 Minutes)

### Step 1: Install Dependencies (1 minute)
```bash
# Activate virtual environment
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Install packages
pip install -r config/requirements.txt
```

### Step 2: Verify Installation (30 seconds)
```bash
python check_system.py
```
✅ Should display: "All systems operational!"

### Step 3: Launch Application (10 seconds)

#### Desktop GUI (Recommended)
```bash
python main.py desktop
```
- No console window
- Dark theme interface
- Click "📧 Email Detector" or "🔒 File Analyzer"

#### Web Interface
```bash
python main.py web
```
- Open browser: http://localhost:5000
- Click "Check Email" or "Scan File"

---

## 📧 Email Detection Testing

### Example 1: Phishing Email
```
Paste into Email Detector:

From: admin@paypa1.com
Subject: Urgent: Account Verification Required

Your account will be suspended!
Click here immediately: http://bit.ly/verify123
```

**Expected Results:**
- 🚨 PHISHING DETECTED
- Risk: High - Critical
- Confidence: 70-95%
- Reasons: Shortened URL (bit.ly), suspicious keywords, domain spoofing

### Example 2: Legitimate Email
```
Paste:

From: github@github.com
Subject: Your weekly digest

Here are this week's trending repositories:
- awesome-python
- tensorflow
```

**Expected Results:**
- ✅ LEGITIMATE EMAIL or ⚠️ UNCERTAIN
- Risk: Safe (70%+) or Uncertain (<50%)
- Confidence: Depends on email features
- Note: If confidence < 50%, system displays "Uncertain" instead of "Legitimate"

---

## 🔒 File Analysis Testing

### Quick Test
```bash
# Create test file
echo "MZ test content" > test.exe

# Analyze via desktop app
1. Click "📁 Browse..."
2. Select test.exe
3. Click "🔍 Analyze File"
```

---

## 🎓 Custom Model Training

### Using Desktop App
1. Go to "🎓 Train Model" tab
2. Select model type: Email or File
3. Click "📁 Select Training Data File"
4. Choose CSV from `data/training_samples/`
5. Click "🚀 Start Training"

### Using Command Line
```bash
python dev/scripts/train_pretrained.py
```

---

## 🔧 Common Commands

```bash
# Desktop application
python main.py desktop

# Web server
python main.py web

# System check
python check_system.py

# Run tests
python dev/tests/test_suite.py

# Train models
python dev/scripts/train_pretrained.py
```

---

## 💡 Tips & Tricks

### Faster Analysis
- Results are automatically cached
- Second analysis of same content is instant
- Clear cache in Settings tab if needed

### Higher Accuracy
- Include full email headers (From, SPF, DKIM, DMARC)
- Provide complete email content (Subject + Body)
- Use full file paths
- Keep models updated

### Understanding Analysis Results
**Risk Levels:**
- `Safe`: Confidence ≥ 70% - Very likely legitimate
- `Low Risk`: Confidence 50-70% - Fairly safe but be cautious
- `Uncertain`: Confidence < 50% - Not sure, manual review needed
- `Low/Medium`: Phishing with low-medium confidence (40-60%)
- `High`: Phishing with high confidence (60-80%)
- `Critical`: Phishing with very high confidence (≥80%)

**Important Notes:**
- "Uncertain" result doesn't mean safe - it means the system is unsure
- Always manually verify emails with confidence < 70%
- Risk factors: Shortened URLs, IP URLs, urgent keywords, information requests

### Troubleshooting
```bash
# Fix missing dependencies
pip install -r config/requirements.txt

# Fix NLTK data
python -c "import nltk; nltk.download('punkt_tab'); nltk.download('stopwords')"

# Reset everything
python check_system.py
```

---

## 📚 Next Steps

1. Read full documentation: `HUONG_DAN.md`
2. Explore training samples: `data/training_samples/`
3. Check optimization report: `OPTIMIZATION_REPORT.md`
4. Run test suite: `python dev/tests/test_suite.py`

---

**Need Help?**
- See `HUONG_DAN.md` for detailed documentation
- Run `python check_system.py` for diagnostics
- Check `OPTIMIZATION_REPORT.md` for system info

**Quick Links:**
- Desktop App: `python main.py desktop`
- Web App: `python main.py web` → http://localhost:5000
- Tests: `python dev/tests/test_suite.py`

---

**Version**: 2.0.0 (Bilingual Edition)  
**Last Updated**: November 15, 2025  
**Languages**: Vietnamese 🇻🇳 | English 🇬🇧
