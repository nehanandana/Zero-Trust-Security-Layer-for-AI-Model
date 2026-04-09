import requests
import json

BASE_URL = "http://127.0.0.1:5000"

def test_health():
    """Test if server is running"""
    print("\nTesting")
    response = requests.get(f"{BASE_URL}/health")
    print(f"Response: {response.json()}")
    return response.status_code == 200

def test_register_success():
    """Test successful registration"""
    print("\nTest 1: Successful Registration")
    
    user_data = {
        "username": "alice",
        "email": "alice@example.com",
        "password": "AliceStrong123"
    }
    
    response = requests.post(f"{BASE_URL}/register", json=user_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    if response.status_code == 201:
        print("PASSED")
        return True
    else:
        print("FAILED")
        return False

def test_duplicate_user():
    """Test duplicate username"""
    print("\nTest 2: Duplicate Username (Should fail)")
    
    user_data = {
        "username": "alice",  # Same as before
        "email": "different@example.com",
        "password": "AnotherPass123"
    }
    
    response = requests.post(f"{BASE_URL}/register", json=user_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 409:
        print("PASSED - Duplicate detected")
        return True
    else:
        print("FAILED")
        return False

def test_weak_password():
    """Test weak password rejection"""
    print("\nTest 3: Weak Password (Should fail)")
    
    user_data = {
        "username": "bob",
        "email": "bob@example.com",
        "password": "weak"
    }
    
    response = requests.post(f"{BASE_URL}/register", json=user_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 400:
        print("PASSED - Weak password rejected")
        return True
    else:
        print(" FAILED")
        return False

def test_invalid_email():
    """Test invalid email format"""
    print("\nTest 4: Invalid Email (Should fail)")
    
    user_data = {
        "username": "charlie",
        "email": "not-an-email",
        "password": "CharlieStrong123"
    }
    
    response = requests.post(f"{BASE_URL}/register", json=user_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 400:
        print(" PASSED - Invalid email rejected")
        return True
    else:
        print("FAILED")
        return False

def test_missing_fields():
    """Test missing password"""
    print("\nTest 5: Missing Password (Should fail)")
    
    user_data = {
        "username": "david",
        "email": "david@example.com"
        # No password
    }
    
    response = requests.post(f"{BASE_URL}/register", json=user_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 400:
        print("PASSED - Missing field detected")
        return True
    else:
        print("FAILED")
        return False

# Run all tests
if __name__ == "__main__":
    print("STARTING TESTS FOR REGISTRATION SYSTEM")
    
    # First check if server is running
    try:
        if not test_health():
            print("\nERROR: Server is not running!")
            print("Please run: python app.py in another terminal")
            exit(1)
    except:
        print("\nERROR: Cannot connect to server!")
        print("Please make sure server is running: python app.py")
        exit(1)
    
    # Run all tests
    test_register_success()
    test_duplicate_user()
    test_weak_password()
    test_invalid_email()
    test_missing_fields()
    
    print("ALL TESTS COMPLETED")