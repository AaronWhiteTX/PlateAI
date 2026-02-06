import sys
import os

# Add backend/lambda to path so we can import the function
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend', 'lambda', 'FoodIdentifierProcessor'))

from lambda_function import validate_email, validate_image_base64, validate_question


class TestValidateEmail:
    """Test email validation function"""
    
    def test_valid_email(self):
        assert validate_email("test@example.com") == True
    
    def test_valid_email_with_dots(self):
        assert validate_email("test.user@example.com") == True
    
    def test_valid_email_with_plus(self):
        assert validate_email("test+tag@example.com") == True
    
    def test_invalid_email_no_at(self):
        assert validate_email("testexample.com") == False
    
    def test_invalid_email_no_domain(self):
        assert validate_email("test@") == False
    
    def test_invalid_email_empty(self):
        assert validate_email("") == False


class TestValidateImageBase64:
    """Test image validation function"""
    
    def test_valid_small_image(self):
        small_image = "a" * 1000  # Small fake base64
        is_valid, error = validate_image_base64(small_image)
        assert is_valid == True
        assert error is None
    
    def test_no_image(self):
        is_valid, error = validate_image_base64(None)
        assert is_valid == False
        assert error == "No image provided"
    
    def test_empty_image(self):
        is_valid, error = validate_image_base64("")
        assert is_valid == False
        assert error == "No image provided"


class TestValidateQuestion:
    """Test question validation function"""
    
    def test_valid_question(self):
        is_valid, error = validate_question("What is protein?")
        assert is_valid == True
        assert error is None
    
    def test_empty_question(self):
        is_valid, error = validate_question("")
        assert is_valid == False
    
    def test_none_question(self):
        is_valid, error = validate_question(None)
        assert is_valid == False
    
    def test_too_long_question(self):
        long_question = "a" * 501
        is_valid, error = validate_question(long_question)
        assert is_valid == False