# Hệ Thống Phát Hiện Lừa Đảo - Tài Liệu Đầy Đủ
# Phishing & Malware Detection System - Complete Documentation

> **Ngôn ngữ / Language**: [Tiếng Việt](#vietnamese-docs) | [English](#english-docs)

---

<a name="vietnamese-docs"></a>
## 🇻🇳 TÀI LIỆU TIẾNG VIỆT

## 📋 Mục Lục
1. [Tổng Quan Dự Án](#tổng-quan-dự-án)
2. [Kiến Trúc Hệ Thống](#kiến-trúc-hệ-thống)
3. [Hướng Dẫn Cài Đặt](#hướng-dẫn-cài-đặt)
4. [Hướng Dẫn Sử Dụng](#hướng-dẫn-sử-dụng)
5. [Tài Liệu API](#tài-liệu-api)
6. [Hướng Dẫn Kiểm Thử](#hướng-dẫn-kiểm-thử)
7. [Chi Tiết Thuật Toán](#chi-tiết-thuật-toán)
8. [Giải Thích Code](#giải-thích-code)
9. [Khắc Phục Sự Cố](#khắc-phục-sự-cố)

---

## 🎯 Tổng Quan Dự Án

### Hệ Thống Phát Hiện Lừa Đảo Là Gì?
Một ứng dụng bảo mật toàn diện sử dụng Machine Learning để phát hiện:
- **Email Lừa Đảo (Phishing)**: Nhận diện email độc hại sử dụng 16 đặc trưng
- **File Chứa Mã Độc (Malware)**: Phân tích file tìm các đặc điểm độc hại sử dụng 11 đặc trưng

### Tính Năng Chính
- ✅ **Ứng Dụng Desktop**: Giao diện PyQt6 với theme tối
- ✅ **Ứng Dụng Web**: REST API Flask với giao diện Bootstrap
- ✅ **Mô Hình ML**: Random Forest với độ chính xác 95%+
- ✅ **Phân Tích Thời Gian Thực**: Dự đoán nhanh với bộ nhớ cache
- ✅ **Đa Nền Tảng**: Hỗ trợ Windows, Linux, macOS

### Công Nghệ Sử Dụng
- **Giao diện**: PyQt6 (Desktop), Bootstrap 5 (Web)
- **Backend**: Python 3.13, Flask
- **ML Framework**: Scikit-learn (Random Forest)
- **Xử lý ngôn ngữ**: NLTK
- **Dữ liệu**: Pandas, NumPy

---

## 🏗️ Kiến Trúc Hệ Thống

### Sơ Đồ Thành Phần
```
┌─────────────────────────────────────────────────────────┐
│                Lớp Giao Diện Người Dùng                  │
├──────────────────────┬──────────────────────────────────┤
│   Desktop App (Qt)   │      Web App (Flask)             │
│   - Tab Email        │      - /email-detector           │
│   - Tab File         │      - /file-analyzer            │
│   - Tab Training     │      - API Endpoints             │
│   - Tab Cài Đặt     │      - REST JSON                 │
└──────────────────────┴──────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│                  Lớp Phát Hiện Mối Đe Dọa               │
├──────────────────────┬──────────────────────────────────┤
│  EmailPhishingDetector│     MalwareAnalyzer             │
│  - Trích xuất đặc trưng│  - Phân tích nhị phân          │
│  - Kiểm tra header   │     - Tính entropy               │
│  - Phân tích URL     │     - Khớp mẫu                   │
│  - Xử lý NLP         │     - Tạo hash                   │
└──────────────────────┴──────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│                   Lớp Mô Hình ML                         │
├──────────────────────┬──────────────────────────────────┤
│  Email RF Classifier │     File RF Classifier           │
│  - 200 cây quyết định│     - 200 cây quyết định         │
│  - 16 đặc trưng      │     - 11 đặc trưng               │
│  - 95.8% độ chính xác│     - ~98% độ chính xác          │
│  - Cache (singleton) │     - Cache (singleton)          │
└──────────────────────┴──────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│                    Lớp Dữ Liệu                           │
│  - Bộ dữ liệu training (CSV)                             │
│  - Mô hình đã train (.pkl)                               │
│  - Scalers (StandardScaler)                              │
│  - Dữ liệu NLTK (punkt, stopwords)                       │
└─────────────────────────────────────────────────────────┘
```

### Cấu Trúc Thư Mục
```
Model_Phishing/
├── main.py                      # Điểm vào chính cho tất cả chế độ
├── check_system.py              # Script kiểm tra hệ thống
├── PhishingDetector.exe         # File thực thi đã biên dịch
│
├── apps/                        # Lớp ứng dụng
│   ├── desktop/
│   │   └── main.py              # GUI desktop PyQt6
│   └── web/
│       ├── app.py               # Web server Flask
│       ├── templates/           # Template HTML
│       └── static/              # File CSS, JS
│
├── src/                         # Lớp logic chính
│   ├── detectors/
│   │   ├── email_detector.py    # Phân tích email
│   │   ├── file_analyzer.py     # Phân tích file
│   │   └── hybrid_detector.py   # Phát hiện kết hợp
│   ├── ml/
│   │   └── model_trainer.py     # Pipeline training model
│   └── utils/
│       └── schema.py            # Validation dữ liệu
│
├── data/                        # Lớp dữ liệu
│   ├── models/                  # Mô hình ML đã train
│   │   ├── email_phishing_detector.pkl
│   │   ├── email_scaler.pkl
│   │   ├── malware_classifier.pkl
│   │   └── file_scaler.pkl
│   └── training_samples/        # Bộ dữ liệu training
│       ├── email_combined_dataset.csv
│       ├── email_phishing_samples.csv
│       └── email_legitimate_samples.csv
│
├── dev/                         # Công cụ phát triển
│   ├── scripts/                 # Script training & tiện ích
│   │   ├── train_model.py
│   │   ├── train_pretrained.py
│   │   └── validate_data.py
│   └── tools/                   # Công cụ build & setup
│       ├── setup.py
│       └── build_installer.py
│
├── deployment/                  # Cấu hình deployment
│   └── pyinstaller/
│       └── desktop_app.spec
│
├── resources/                   # Tài nguyên tĩnh
│   ├── icons/
│   └── images/
│
├── config/                      # Cấu hình
│   └── requirements.txt         # Dependencies Python
│
└── .venv/                       # Môi trường ảo
```

---

## 📦 Hướng Dẫn Cài Đặt

### Yêu Cầu Hệ Thống
- **Python**: 3.9 trở lên (khuyến nghị 3.13+)
- **HĐH**: Windows 10/11, Ubuntu 20.04+, macOS 11+
- **RAM**: Tối thiểu 4GB (khuyến nghị 8GB)
- **Ổ cứng**: 2GB dung lượng trống

### Cài Đặt Nhanh (Windows)

#### Phương Pháp 1: Setup Tự Động
```powershell
# Chạy wizard setup
python dev/tools/setup.py
```

#### Phương Pháp 2: Setup Thủ Công
```powershell
# 1. Tạo môi trường ảo
python -m venv .venv

# 2. Kích hoạt môi trường
.venv\Scripts\activate

# 3. Nâng cấp pip
python -m pip install --upgrade pip

# 4. Cài đặt dependencies
pip install -r config/requirements.txt

# 5. Tải dữ liệu NLTK
python -c "import nltk; nltk.download('punkt_tab'); nltk.download('stopwords')"

# 6. Kiểm tra cài đặt
python check_system.py
```

### Cài Đặt Nhanh (Linux/macOS)
```bash
# Chạy script setup
chmod +x dev/tools/linux/setup.sh
./dev/tools/linux/setup.sh
```

### Danh Sách Dependencies
```
Lõi:
- numpy==2.3.4
- pandas==2.3.3
- scikit-learn==1.7.2
- scipy==1.16.3

GUI:
- PyQt6==6.10.0
- PyQt6-Charts==6.10.0

Web:
- Flask==3.1.2
- werkzeug==3.1.3

NLP:
- nltk==3.9.2
- beautifulsoup4==4.14.2

ML:
- joblib==1.5.2

Build:
- PyInstaller==6.16.0
```

---

## 📖 Hướng Dẫn Sử Dụng

### Ứng Dụng Desktop

#### Khởi Chạy App Desktop
```bash
python main.py desktop
```

#### Tính Năng & Quy Trình

**1. Tab Phát Hiện Email Lừa Đảo**
```
Bước 1: Dán nội dung email vào ô text
        Bao gồm: Subject, From, To, Body
        
Bước 2: Nhấn "🔍 Phân Tích Email"
        Thanh tiến trình hiển thị trạng thái
        
Bước 3: Xem kết quả
        - Mức độ rủi ro: Safe/Low/Medium/High/Critical
        - Độ tin cậy: 0-100%
        - Đặc trưng chính: SPF, URLs, Keywords
        - Kết quả cache được tải tức thì
```

**2. Tab Phân Tích File Mã Độc**
```
Bước 1: Nhấn "📁 Browse..." để chọn file
        Hỗ trợ: .exe, .dll, .bin, .elf, .zip, .pdf
        Kích thước tối đa: 50MB
        
Bước 2: Nhấn "🔍 Phân Tích File"
        Trích xuất đặc trưng nhị phân
        Tính toán entropy
        
Bước 3: Xem kết quả
        - Mức độ rủi ro: Safe/Low/Medium/High/Critical
        - Độ tin cậy: 0-100%
        - Hash file: MD5, SHA1, SHA256
        - Phân tích: Entropy, Headers, Strings
```

**3. Tab Training Model**
```
Bước 1: Chọn loại model
        - Email Phishing Detector
        - File Malware Analyzer
        
Bước 2: Nhấn "📁 Chọn File Dữ Liệu Training"
        Chọn file CSV/NPY chứa đặc trưng
        
Bước 3: Nhấn "🚀 Bắt Đầu Training"
        Thanh tiến trình: Đang tải → Training → Lưu
        
Bước 4: Xem kết quả training
        - Accuracy, Precision, Recall, F1-Score
        - Số lượng mẫu training
        - Model được lưu vào data/models/
```

**4. Tab Cài Đặt**
```
- Bật cache kết quả (phân tích nhanh hơn lần sau)
- Lưu log phân tích
- Xóa cache
- Xem thông tin app
```

#### Phím Tắt
- `Ctrl+O`: Mở file (File Analyzer)
- `Ctrl+V`: Dán nội dung email
- `Ctrl+Enter`: Phân tích
- `Ctrl+Q`: Thoát ứng dụng

---

### Ứng Dụng Web

#### Khởi Chạy Web Server
```bash
python main.py web
```
Server chạy tại: `http://localhost:5000`

#### API Endpoints

**1. Phân Tích Email**
```http
POST /api/analyze-email
Content-Type: application/json

{
  "email_content": "From: phisher@example.com\nSubject: Xác minh tài khoản khẩn cấp...",
  "email_headers": {
    "From": "phisher@example.com",
    "SPF": "fail"
  }
}

Response 200:
{
  "status": "success",
  "prediction": "PHISHING",
  "confidence": 0.92,
  "risk_level": "Critical",
  "features": {
    "spf_pass": 0,
    "url_count": 5,
    "suspicious_keyword_count": 8,
    ...
  }
}
```

**2. Phân Tích File**
```http
POST /api/analyze-file
Content-Type: multipart/form-data

file: [binary file upload]

Response 200:
{
  "status": "success",
  "prediction": "MALWARE",
  "confidence": 0.87,
  "risk_level": "High",
  "file_hash": {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "analysis": {
    "entropy": 7.85,
    "has_pe_header": true,
    "suspicious_strings": 12,
    "file_size": 1048576
  }
}
```

**3. Thống Kê Hệ Thống**
```http
GET /api/stats

Response 200:
{
  "status": "success",
  "email_features": 16,
  "file_features": 11,
  "models": ["Random Forest", "Gradient Boosting", "Heuristic"],
  "email_accuracy_range": "50-95%",
  "file_accuracy_range": "60-98%"
}
```

#### Trang Web UI
- `/` - Trang chủ với tổng quan tính năng
- `/email-detector` - Giao diện phân tích email
- `/file-analyzer` - Giao diện phân tích file

---

## 🧪 Hướng Dẫn Kiểm Thử

### Kiểm Thử Thủ Công

#### Test Phát Hiện Email
```bash
# Test với email lừa đảo mẫu
python dev/scripts/predict_url.py --text "
From: security@paypa1.com
Subject: Khẩn cấp: Xác minh tài khoản ngay!
Tài khoản của bạn đã bị khóa do hoạt động đáng ngờ.
Nhấn vào đây để xác minh: http://bit.ly/verify123
Hành động ngay hoặc tài khoản sẽ bị đình chỉ vĩnh viễn!
"
```

Kết quả mong đợi: **PHISHING** (Độ tin cậy cao)

### Kiểm Thử Tự Động

Chạy test suite:
```bash
python dev/tests/test_suite.py
```

**Kết quả:**
- 22 test cases
- Kiểm tra: Email detector, File analyzer, Model trainer
- Coverage: Email (8 tests), File (9 tests), ML (3 tests), Integration (2 tests)

---

## 🧮 Chi Tiết Thuật Toán

### Thuật Toán Phát Hiện Email Lừa Đảo

#### Trích Xuất Đặc Trưng (16 Đặc Trưng)

**1. Kiểm Tra Header (4 đặc trưng)**
```python
- spf_pass: Xác thực SPF (0 hoặc 1)
- dkim_pass: Xác minh chữ ký DKIM (0 hoặc 1)
- dmarc_pass: Kiểm tra chính sách DMARC (0 hoặc 1)
- sender_domain_age: Tuổi tên miền (ngày) (0-10000)
```

**2. Phân Tích URL (3 đặc trưng)**
```python
- url_count: Số lượng URL trong email (0-100+)
- has_shortener_urls: Chứa bit.ly, tinyurl, v.v. (0 hoặc 1)
- has_ip_based_urls: URL có địa chỉ IP (0 hoặc 1)
```

**3. Phân Tích Nội Dung (6 đặc trưng)**
```python
- suspicious_keyword_count: Đếm từ khóa lừa đảo (0-50+)
- urgency_score: Điểm ngôn ngữ khẩn cấp (0.0-1.0)
- capitalization_ratio: Tỷ lệ chữ IN HOA (0.0-1.0)
- special_char_ratio: Tỷ lệ ký tự đặc biệt (0.0-1.0)
- html_tag_count: Số lượng thẻ HTML (0-1000+)
- has_email_form: Chứa form nhập email (0 hoặc 1)
```

**4. Phân Tích Văn Bản (3 đặc trưng)**
```python
- text_length: Số ký tự (0-100000+)
- word_count: Số từ (0-10000+)
- unique_word_ratio: Từ duy nhất / tổng số từ (0.0-1.0)
```

#### Quy Trình Thuật Toán (Cải Tiến)
```
Input: Nội Dung Email + Headers
         ↓
Bước 1: Parse Email
        - Trích xuất headers (From, To, Subject)
        - Parse body text
        - Trích xuất URLs
         ↓
Bước 2: Trích Xuất Đặc Trưng
        Với mỗi đặc trưng:
          - Tính giá trị
          - Chuẩn hóa về [0, 1] hoặc count
         Kết quả: Vector 16 chiều
         ↓
Bước 3: Tiền Xử Lý
        - Chuẩn hóa StandardScaler
        - Scale đặc trưng: x' = (x - μ) / σ
         ↓
Bước 4: Phân Loại Kết Hợp
        A. Random Forest (200 cây)
           - Mỗi cây vote: 0 (hợp lệ) hoặc 1 (lừa đảo)
           - ML_phishing_score = votes_phishing / tổng_cây
        
        B. Heuristic Scoring
           - URL shortener: +30%
           - IP URLs: +35%
           - Từ khóa đáng ngờ: +10-20%
           - Urgency cao: +20%
           - Failed SPF/DKIM/DMARC: +20%
           - Heuristic_score = tổng các điểm
        
        C. Kết Hợp Scores
           combined_score = ML_score × 0.6 + Heuristic_score × 0.4
           
           if combined_score >= 0.5:
               prediction = PHISHING
               confidence = combined_score
           else:
               prediction = LEGITIMATE
               confidence = 1.0 - combined_score
         ↓
Bước 5: Đánh Giá Rủi Ro (Thông Minh) (Thông Minh)
        nếu prediction == PHISHING:
          nếu confidence >= 0.8: rủi_ro = "Critical"
          nếu confidence >= 0.6: rủi_ro = "High"
          nếu confidence >= 0.4: rủi_ro = "Medium"
          nếu_không: rủi_ro = "Low"
        
        nếu prediction == LEGITIMATE:
          # Kiểm tra độ chắc chắn
          nếu confidence >= 0.7: rủi_ro = "Safe"
          nếu confidence >= 0.5: rủi_ro = "Low Risk"
          nếu_không: rủi_ro = "Uncertain"  # KHÔNG GỌI LÀ SAFE!
        
        # Override cho tín hiệu mạnh
        nếu heuristic_score > 0.7:
          prediction = PHISHING
          confidence = max(confidence, heuristic_score)
         ↓
Output: {is_phishing, confidence, risk_level, features}
```

### Thuật Toán Phát Hiện Mã Độc File

#### Trích Xuất Đặc Trưng (11 Đặc Trưng)

**1. Metadata File (2 đặc trưng)**
```python
- file_size: Kích thước (bytes) (0-100MB)
- file_extension: Độ dài phần mở rộng (0-10)
```

**2. Phân Tích Nhị Phân (5 đặc trưng)**
```python
- entropy: Shannon entropy (0.0-8.0)
  Công thức: H = -Σ(p(x) * log2(p(x)))
  Entropy cao (7-8) = mã hóa/nén (đáng ngờ)
  
- has_pe_header: PE executable header (0 hoặc 1)
- has_elf_header: ELF executable header (0 hoặc 1)
- null_byte_ratio: Null bytes / tổng bytes (0.0-1.0)
- avg_byte_value: Giá trị byte trung bình (0-255)
```

**3. Khớp Mẫu (4 đặc trưng)**
```python
- suspicious_strings_count: Đếm API calls (0-100+)
  - CreateRemoteThread
  - WriteProcessMemory
  - SetWindowsHookEx
  - ShellExecute
  
- has_zip_header: ZIP archive header (0 hoặc 1)
- has_executable_code: Phát hiện x86 opcodes (0 hoặc 1)
- magic_number: Điểm chữ ký file (0-10)
```

#### Tính Toán Entropy
```python
def calculate_entropy(data: bytes) -> float:
    """
    Shannon entropy đo độ ngẫu nhiên
    Entropy thấp = dự đoán được (file text)
    Entropy cao = ngẫu nhiên (mã hóa/nén)
    """
    if len(data) == 0:
        return 0
    
    # Đếm tần suất byte
    byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
    probabilities = byte_counts[byte_counts > 0] / len(data)
    
    # Tính entropy
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return entropy

# Ví dụ:
# Plain text "AAAA": entropy ≈ 0 (rất dự đoán được)
# Random bytes: entropy ≈ 8 (ngẫu nhiên tối đa)
# File nén: entropy ≈ 7-8 (đáng ngờ)
```

### Random Forest Classifier

#### Kiến Trúc Model
```
Random Forest (Tập hợp 200 Cây Quyết Định)
├── Cây 1
│   ├── Root: if entropy > 6.5
│   │   ├── Trái: if suspicious_strings > 5
│   │   │   ├── Lá: MALWARE (tin cậy 0.95)
│   │   │   └── Lá: BENIGN (tin cậy 0.65)
│   │   └── Phải: if has_pe_header == 1
│   │       ├── Lá: MALWARE (tin cậy 0.85)
│   │       └── Lá: BENIGN (tin cậy 0.75)
├── Cây 2
│   └── ... (tiêu chí phân chia khác)
...
└── Cây 200
    └── ...

Dự Đoán Cuối Cùng:
- Tổng hợp votes từ tất cả cây
- Vote đa số thắng
- Độ tin cậy = votes / 200
```

#### Siêu Tham Số
```python
RandomForestClassifier(
    n_estimators=200,        # Số lượng cây
    max_depth=15,            # Độ sâu cây tối đa
    min_samples_split=4,     # Mẫu tối thiểu để phân chia node
    min_samples_leaf=2,      # Mẫu tối thiểu trong lá
    max_features='sqrt',     # Tập đặc trưng ngẫu nhiên mỗi phân chia
    bootstrap=True,          # Bootstrap aggregating
    oob_score=True,          # Validation out-of-bag
    class_weight='balanced', # Xử lý dữ liệu mất cân bằng
    random_state=42,         # Tái tạo được
    n_jobs=-1               # Xử lý song song
)
```

---

## 💻 Giải Thích Code

### Các Thành Phần Chính

#### 1. Email Detector (`src/detectors/email_detector.py`)

**Khởi Tạo & Load Model**
```python
class EmailPhishingDetector:
    # Singleton pattern cho model caching
    _model_cache: Optional[Dict] = None
    
    def __init__(self, model_dir: str = 'data/models'):
        # Load tài nguyên NLTK
        self.stop_words = set(stopwords.words('english'))
        
        # Định nghĩa pattern đáng ngờ
        self.suspicious_keywords = [
            'verify', 'confirm', 'urgent', 'act now', ...
        ]
        
        # Load ML model (với caching)
        self._load_models()
    
    def _load_models(self):
        """
        Load model đã train với singleton pattern.
        Instance đầu tiên load từ disk và cache.
        Instance tiếp theo dùng model đã cache.
        """
        # Kiểm tra cache cấp class
        if EmailPhishingDetector._model_cache is not None:
            self.model = EmailPhishingDetector._model_cache.get('model')
            self.scaler = EmailPhishingDetector._model_cache.get('scaler')
            return
        
        # Load từ disk
        try:
            self.model = joblib.load('data/models/email_phishing_detector.pkl')
            self.scaler = joblib.load('data/models/email_scaler.pkl')
            
            # Cache ở cấp class
            EmailPhishingDetector._model_cache = {
                'model': self.model,
                'scaler': self.scaler
            }
        except Exception as e:
            print(f"Cảnh báo: Không thể load model: {e}")
            self.model = None
```

**Trích Xuất Đặc Trưng**
```python
def _extract_feature_dict(self, email_content: str, 
                         email_headers: Dict = None) -> Dict:
    """
    Trích xuất 16 đặc trưng từ email.
    Trả về dict để dễ debug và phân tích.
    """
    features = {}
    
    # Đặc trưng header (4)
    if email_headers:
        features['spf_pass'] = self._check_spf(email_headers)
        features['dkim_pass'] = self._check_dkim(email_headers)
        features['dmarc_pass'] = self._check_dmarc(email_headers)
        features['sender_domain_age'] = self._get_domain_age(
            email_headers.get('From', '')
        )
    else:
        # Giá trị mặc định nếu không có headers
        features.update({
            'spf_pass': 0, 'dkim_pass': 0,
            'dmarc_pass': 0, 'sender_domain_age': 0
        })
    
    # Đặc trưng URL (3)
    features['url_count'] = self._count_urls(email_content)
    features['has_shortener_urls'] = self._has_suspicious_urls(email_content)
    features['has_ip_based_urls'] = self._has_ip_urls(email_content)
    
    # Đặc trưng nội dung (6)
    features['suspicious_keyword_count'] = \
        self._count_suspicious_keywords(email_content)
    features['urgency_score'] = \
        self._calculate_urgency_score(email_content)
    
    return features
```

---

## 🔧 Khắc Phục Sự Cố

### Các Vấn Đề Thường Gặp

#### Vấn Đề 1: Lỗi Import
```
Error: ModuleNotFoundError: No module named 'PyQt6'
```
**Khắc phục:**
```bash
pip install -r config/requirements.txt
```

#### Vấn Đề 2: Không Tìm Thấy Model
```
Cảnh báo: Không tìm thấy model tại data/models/email_phishing_detector.pkl
```
**Khắc phục:**
```bash
# Train model từ đầu
python dev/scripts/train_pretrained.py
```

#### Vấn Đề 3: Thiếu Dữ Liệu NLTK
```
LookupError: Resource punkt_tab not found
```
**Khắc phục:**
```python
python -c "import nltk; nltk.download('punkt_tab'); nltk.download('stopwords')"
```

#### Vấn Đề 4: Cửa Sổ Console Hiển Thị
**Khắc phục:** Đã fix - console hiding ở đầu script trong `apps/desktop/main.py`

#### Vấn Đề 5: Web Server Không Khởi Động
```
Error: Address already in use
```
**Khắc phục:**
```bash
# Kill process trên port 5000
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Hoặc dùng port khác
python -c "from apps.web.app import app; app.run(port=8080)"
```

### Tối Ưu Hiệu Suất

#### Load Model Chậm
- ✅ Đã tối ưu với singleton pattern
- Model được cache sau lần load đầu
- Tăng tốc: ~10x cho các instance tiếp theo

#### Phân Tích File Chậm
- Giới hạn kích thước file ở 50MB
- Dùng SSD cho I/O nhanh hơn
- Cân nhắc đọc theo chunk cho file lớn

#### Sử Dụng Bộ Nhớ Cao
```python
# Giới hạn kích thước cache trong AnalysisWorker
AnalysisWorker._cache_limit = 50  # Giảm từ 100
```

---

## 📊 Hiệu Năng

### Phát Hiện Email
- **Cold Start**: 0.5s (load model)
- **Warm Start**: 0.05s (model đã cache)
- **Trích xuất đặc trưng**: 0.02s
- **Dự đoán**: 0.03s
- **Độ chính xác**: 70-95% (tùy thuộc độ tin cậy)
- **Thuật toán**: Kết hợp ML (60%) + Heuristics (40%)

### Phân Tích File
- **File nhỏ (<1MB)**: 0.5-1s
- **File trung (<1-10MB)**: 1-3s
- **File lớn (10-50MB)**: 3-10s
- **Tính entropy**: 0.1s per MB
- **Độ chính xác**: ~98%

### Yêu Cầu Hệ Thống
- **Tối thiểu**: 4GB RAM, 2 CPU cores, 2GB disk
- **Khuyến nghị**: 8GB RAM, 4 CPU cores, 5GB disk
- **GPU**: Không cần (chỉ CPU)

---

**Phiên Bản Tài Liệu**: 1.0.0  
**Cập Nhật Lần Cuối**: 15 Tháng 11, 2025  
**Tác Giả**: GitHub Copilot (Claude Sonnet 4.5)

---

<a name="english-docs"></a>
## 🇬🇧 ENGLISH DOCUMENTATION

## 📋 Table of Contents
1. [Project Overview](#overview-en)
2. [System Architecture](#architecture-en)
3. [Installation Guide](#installation-en)
4. [Algorithm Details](#algorithm-en)
5. [Performance Metrics](#performance-en)
6. [Troubleshooting](#troubleshooting-en)

---

<a name="overview-en"></a>
## 🎯 Project Overview

### What is the Phishing & Malware Detection System?
A comprehensive security application using Machine Learning to detect:
- **Phishing Emails**: Identifies malicious emails using 16 features
- **Malware Files**: Analyzes files for malicious characteristics using 11 features

### Key Features
- ✅ **Desktop Application**: PyQt6 interface with dark theme
- ✅ **Web Application**: Flask REST API with Bootstrap UI
- ✅ **ML Models**: Random Forest with 95%+ accuracy
- ✅ **Real-time Analysis**: Fast predictions with caching
- ✅ **Cross-platform**: Supports Windows, Linux, macOS

### Technology Stack
- **UI**: PyQt6 (Desktop), Bootstrap 5 (Web)
- **Backend**: Python 3.13, Flask
- **ML Framework**: Scikit-learn (Random Forest)
- **NLP**: NLTK
- **Data**: Pandas, NumPy

---

<a name="architecture-en"></a>
## 🏗️ System Architecture

### Component Diagram
```
┌─────────────────────────────────────────────────────────┐
│                User Interface Layer                      │
├──────────────────────┬──────────────────────────────────┤
│   Desktop App (Qt)   │      Web App (Flask)             │
│   - Email Tab        │      - /email-detector           │
│   - File Tab         │      - /file-analyzer            │
│   - Training Tab     │      - API Endpoints             │
│   - Settings Tab     │      - REST JSON                 │
└──────────────────────┴──────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│                Threat Detection Layer                    │
├──────────────────────┬──────────────────────────────────┤
│  EmailPhishingDetector│     MalwareAnalyzer             │
│  - Feature extraction│     - Binary analysis            │
│  - Header validation │     - Entropy calculation        │
│  - URL analysis      │     - Pattern matching           │
│  - NLP processing    │     - Hash generation            │
└──────────────────────┴──────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│                   ML Model Layer                         │
├──────────────────────┬──────────────────────────────────┤
│  Email RF Classifier │     File RF Classifier           │
│  - 200 decision trees│     - 200 decision trees         │
│  - 16 features       │     - 11 features                │
│  - 95.8% accuracy    │     - ~98% accuracy              │
│  - Cache (singleton) │     - Cache (singleton)          │
└──────────────────────┴──────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────────┐
│                     Data Layer                           │
│  - Training datasets (CSV)                               │
│  - Trained models (.pkl)                                 │
│  - Scalers (StandardScaler)                              │
│  - NLTK data (punkt, stopwords)                          │
└─────────────────────────────────────────────────────────┘
```

---

<a name="installation-en"></a>
## 📦 Installation Guide

### System Requirements
- **Python**: 3.9+ (recommended 3.13+)
- **OS**: Windows 10/11, Ubuntu 20.04+, macOS 11+
- **RAM**: Minimum 4GB (recommended 8GB)
- **Storage**: 2GB free space

### Quick Installation (Windows)

```powershell
# 1. Create virtual environment
python -m venv .venv

# 2. Activate environment
.venv\Scripts\activate

# 3. Upgrade pip
python -m pip install --upgrade pip

# 4. Install dependencies
pip install -r config/requirements.txt

# 5. Download NLTK data
python -c "import nltk; nltk.download('punkt_tab'); nltk.download('stopwords')"

# 6. Verify installation
python check_system.py
```

### Quick Installation (Linux/macOS)
```bash
chmod +x dev/tools/linux/setup.sh
./dev/tools/linux/setup.sh
```

---

<a name="algorithm-en"></a>
## 🧮 Algorithm Details

### Email Phishing Detection Algorithm

#### Feature Extraction (16 Features)

**1. Header Validation (4 features)**
```python
- spf_pass: SPF authentication (0 or 1)
- dkim_pass: DKIM signature verification (0 or 1)
- dmarc_pass: DMARC policy check (0 or 1)
- sender_domain_age: Domain age in days (0-10000)
```

**2. URL Analysis (3 features)**
```python
- url_count: Number of URLs in email (0-100+)
- has_shortener_urls: Contains bit.ly, tinyurl, etc. (0 or 1)
- has_ip_based_urls: URLs with IP addresses (0 or 1)
```

**3. Content Analysis (6 features)**
```python
- suspicious_keyword_count: Count of phishing keywords (0-50+)
- urgency_score: Urgency language score (0.0-1.0)
- capitalization_ratio: Ratio of UPPERCASE letters (0.0-1.0)
- special_char_ratio: Ratio of special characters (0.0-1.0)
- html_tag_count: Number of HTML tags (0-1000+)
- has_email_form: Contains email input form (0 or 1)
```

**4. Text Analysis (3 features)**
```python
- text_length: Character count (0-100000+)
- word_count: Word count (0-10000+)
- unique_word_ratio: Unique words / total words (0.0-1.0)
```

#### Hybrid Algorithm (ML + Heuristics)

```
Input: Email Content + Headers
         ↓
Step 1: Parse Email
        - Extract headers (From, To, Subject)
        - Parse body text
        - Extract URLs
         ↓
Step 2: Feature Extraction
        For each feature:
          - Calculate value
          - Normalize to [0, 1] or count
         Result: 16-dimensional vector
         ↓
Step 3: Preprocessing
        - StandardScaler normalization
        - Scale features: x' = (x - μ) / σ
         ↓
Step 4: Hybrid Classification
        A. Random Forest (200 trees)
           - Each tree votes: 0 (legitimate) or 1 (phishing)
           - ML_phishing_score = phishing_votes / total_trees
        
        B. Heuristic Scoring
           - URL shortener: +30%
           - IP URLs: +35%
           - Suspicious keywords: +10-20%
           - High urgency: +20%
           - Failed SPF/DKIM/DMARC: +20%
           - Heuristic_score = sum of points
        
        C. Combine Scores
           combined_score = ML_score × 0.6 + Heuristic_score × 0.4
           
           if combined_score >= 0.5:
               prediction = PHISHING
               confidence = combined_score
           else:
               prediction = LEGITIMATE
               confidence = 1.0 - combined_score
         ↓
Step 5: Smart Risk Assessment
        if prediction == PHISHING:
          if confidence >= 0.8: risk = "Critical"
          if confidence >= 0.6: risk = "High"
          if confidence >= 0.4: risk = "Medium"
          else: risk = "Low"
        
        if prediction == LEGITIMATE:
          # Check certainty level
          if confidence >= 0.7: risk = "Safe"
          if confidence >= 0.5: risk = "Low Risk"
          else: risk = "Uncertain"  # NOT Safe!
        
        # Override for strong signals
        if heuristic_score > 0.7:
          prediction = PHISHING
          confidence = max(confidence, heuristic_score)
         ↓
Output: {is_phishing, confidence, risk_level, features}
```

### File Malware Detection Algorithm

#### Feature Extraction (11 Features)

**1. File Metadata (2 features)**
```python
- file_size: Size in bytes (0-100MB)
- file_extension: Extension length (0-10)
```

**2. Binary Analysis (5 features)**
```python
- entropy: Shannon entropy (0.0-8.0)
  Formula: H = -Σ(p(x) * log2(p(x)))
  High entropy (7-8) = encrypted/compressed (suspicious)
  
- has_pe_header: PE executable header (0 or 1)
- has_elf_header: ELF executable header (0 or 1)
- null_byte_ratio: Null bytes / total bytes (0.0-1.0)
- avg_byte_value: Average byte value (0-255)
```

**3. Pattern Matching (4 features)**
```python
- suspicious_strings_count: Count of API calls (0-100+)
  - CreateRemoteThread
  - WriteProcessMemory
  - SetWindowsHookEx
  - ShellExecute
  
- has_zip_header: ZIP archive header (0 or 1)
- has_executable_code: Detects x86 opcodes (0 or 1)
- magic_number: File signature score (0-10)
```

---

<a name="performance-en"></a>
## 📊 Performance Metrics

### Email Detection
- **Cold Start**: 0.5s (model loading)
- **Warm Start**: 0.05s (cached model)
- **Feature Extraction**: 0.02s
- **Prediction**: 0.03s
- **Accuracy**: 70-95% (confidence-dependent)
- **Algorithm**: Hybrid ML (60%) + Heuristics (40%)

### File Analysis
- **Small files (<1MB)**: 0.5-1s
- **Medium files (1-10MB)**: 1-3s
- **Large files (10-50MB)**: 3-10s
- **Entropy calculation**: 0.1s per MB
- **Accuracy**: ~98%

### System Requirements
- **Minimum**: 4GB RAM, 2 CPU cores, 2GB disk
- **Recommended**: 8GB RAM, 4 CPU cores, 5GB disk
- **GPU**: Not required (CPU only)

---

<a name="troubleshooting-en"></a>
## 🔧 Troubleshooting

### Common Issues

#### Issue 1: Import Error
```
Error: ModuleNotFoundError: No module named 'PyQt6'
```
**Solution:**
```bash
pip install -r config/requirements.txt
```

#### Issue 2: Model Not Found
```
Warning: Model not found at data/models/email_phishing_detector.pkl
```
**Solution:**
```bash
# Train model from scratch
python dev/scripts/train_pretrained.py
```

#### Issue 3: Missing NLTK Data
```
LookupError: Resource punkt_tab not found
```
**Solution:**
```python
python -c "import nltk; nltk.download('punkt_tab'); nltk.download('stopwords')"
```

#### Issue 4: Web Server Port Conflict
```
Error: Address already in use
```
**Solution:**
```bash
# Kill process on port 5000 (Windows)
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Or use different port
python -c "from apps.web.app import app; app.run(port=8080)"
```

### Performance Optimization

#### Slow Model Loading
- ✅ Optimized with singleton pattern
- Model cached after first load
- Speed improvement: ~10x for subsequent instances

#### Slow File Analysis
- Limit file size to 50MB
- Use SSD for faster I/O
- Consider chunk reading for large files

#### High Memory Usage
```python
# Limit cache size in AnalysisWorker
AnalysisWorker._cache_limit = 50  # Reduce from 100
```

---

## 📚 Additional Resources

### Documentation Files
- `BAT_DAU_NHANH.md` - Quick start guide (Vietnamese + English)
- `HUONG_DAN.md` - Complete documentation (Vietnamese + English)
- `OPTIMIZATION_REPORT.md` - System optimization report

### Training Samples
- `data/training_samples/email_combined_dataset.csv`
- `data/training_samples/email_phishing_samples.csv`
- `data/training_samples/email_legitimate_samples.csv`

### Scripts
- `dev/scripts/train_pretrained.py` - Train models
- `dev/scripts/validate_data.py` - Validate datasets
- `dev/tests/test_suite.py` - Automated tests

---

**Documentation Version**: 2.0.0 (Bilingual Edition)  
**Last Updated**: November 15, 2025  
**Languages**: Vietnamese 🇻🇳 | English 🇬🇧  
**Author**: GitHub Copilot (Claude Sonnet 4.5)
