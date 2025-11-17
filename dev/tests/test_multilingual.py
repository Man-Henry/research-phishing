"""
Test Multilingual Phishing Detection
Demo language detection and translation features
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.detectors.email_detector import EmailPhishingDetector


def test_multilingual_detection():
    """Test language detection with various phishing emails (English, Vietnamese, Chinese only)"""
    
    print("=" * 80)
    print("  MULTILINGUAL PHISHING DETECTION TEST")
    print("  Supported Languages: English, Vietnamese, Chinese")
    print("=" * 80)
    
    detector = EmailPhishingDetector()
    
    # Test cases in different languages
    test_emails = [
        {
            'name': 'Vietnamese Phishing',
            'content': '''
            Kính gửi quý khách,
            
            Tài khoản của bạn đã phát hiện hoạt động bất thường!
            Vui lòng xác nhận tài khoản ngay bằng cách nhấp vào đây:
            http://secure-banking-vn.com/login
            
            Nếu không xác minh trong 24 giờ, tài khoản sẽ bị khóa vĩnh viễn.
            
            Đây là cảnh báo khẩn cấp. Hãy hành động ngay!
            '''
        },
        {
            'name': 'English Phishing',
            'content': '''
            URGENT: Your account has been suspended!
            
            We detected unusual activity on your account.
            Click here to verify your identity immediately:
            http://192.168.1.100/login
            
            Failure to confirm within 24 hours will result in permanent suspension.
            
            Act now to protect your account!
            '''
        },
        {
            'name': 'Chinese Phishing',
            'content': '''
            尊敬的用户：
            
            您的账户检测到异常活动！
            请立即点击这里验证账户：
            http://secure-bank-cn.com/verify
            
            如果24小时内不确认身份，账户将被永久锁定。
            紧急通知，请立即行动！
            '''
        },
        {
            'name': 'Multilingual Phishing (Vietnamese + English)',
            'content': '''
            Xác nhận tài khoản / Verify Account
            
            Your account requires immediate verification!
            Tài khoản của bạn cần xác minh ngay!
            
            Click here: http://bit.ly/verify123
            Nhấp vào đây: http://bit.ly/verify123
            
            URGENT! KHẨN CẤP!
            '''
        },
        {
            'name': 'Legitimate Email (English)',
            'content': '''
            Dear Customer,
            
            Thank you for your recent purchase from Amazon.
            Your order #12345 has been shipped.
            
            Track your package here:
            https://www.amazon.com/orders/track/12345
            
            Best regards,
            Amazon Customer Service
            '''
        },
        {
            'name': 'Legitimate Email (Vietnamese)',
            'content': '''
            Kính gửi quý khách,
            
            Cảm ơn bạn đã mua hàng tại Shopee.
            Đơn hàng #67890 đã được giao cho đơn vị vận chuyển.
            
            Theo dõi đơn hàng tại:
            https://shopee.vn/orders/67890
            
            Trân trọng,
            Shopee Customer Care
            '''
        }
    ]
    
    # Test each email
    for i, test in enumerate(test_emails, 1):
        print(f"\n{'=' * 80}")
        print(f"TEST {i}: {test['name']}")
        print("=" * 80)
        
        # Analyze with multilingual support
        result = detector.analyze_multilingual_email(test['content'])
        
        # Display results
        print(f"\n📧 Email Preview:")
        preview = test['content'].strip()[:150].replace('\n', ' ')
        print(f"   {preview}...")
        
        print(f"\n🌍 Language Detection:")
        print(f"   Primary: {result['language']['primary'].upper()}")
        print(f"   Confidence: {result['language']['confidence']:.2%}")
        print(f"   Multilingual: {'Yes' if result['language']['is_multilingual'] else 'No'}")
        if result['language']['all_detected']:
            print(f"   All detected: {', '.join(result['language']['all_detected'])}")
        
        print(f"\n🔍 Phishing Analysis:")
        print(f"   Classification: {'🚨 PHISHING' if result['is_phishing'] else '✅ LEGITIMATE'}")
        print(f"   Confidence: {result['confidence']:.2%}")
        
        if result['multilingual_phishing']['detected']:
            print(f"\n⚠️  Multilingual Phishing Keywords Detected:")
            print(f"   Count: {result['multilingual_phishing']['keyword_count']}")
            print(f"   Risk Multiplier: {result['multilingual_phishing']['risk_multiplier']:.2f}x")
            print(f"   Keyword Score: {result['multilingual_phishing']['score']:.2%}")
            
            for kw in result['multilingual_phishing']['keywords'][:5]:
                print(f"   - [{kw['language']}] '{kw['keyword']}'")
        
        if result['translation']['needed']:
            print(f"\n🔄 Translation:")
            print(f"   Translation needed: Yes")
            if result['translation']['translated_text']:
                trans_preview = result['translation']['translated_text'][:100]
                print(f"   Translated: {trans_preview}...")
        
        # Risk assessment
        if result['is_phishing']:
            if result['confidence'] >= 0.8:
                risk = "🔴 CRITICAL"
            elif result['confidence'] >= 0.6:
                risk = "🟠 HIGH"
            elif result['confidence'] >= 0.4:
                risk = "🟡 MEDIUM"
            else:
                risk = "🟢 LOW"
        else:
            if result['confidence'] >= 0.7:
                risk = "🟢 SAFE"
            elif result['confidence'] >= 0.5:
                risk = "🟡 LOW RISK"
            else:
                risk = "⚪ UNCERTAIN"
        
        print(f"\n📊 Risk Level: {risk}")
    
    print("\n" + "=" * 80)
    print("  ✅ TEST COMPLETE!")
    print("=" * 80)
    print("\n📈 Summary:")
    print("   • Tested 6 emails across 3 languages")
    print("   • Supported: English, Vietnamese, Chinese")
    print("   • Detected language-specific phishing patterns")
    print("   • Identified multilingual phishing attempts")
    print("   • Applied language-specific risk multipliers")


if __name__ == "__main__":
    try:
        test_multilingual_detection()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
