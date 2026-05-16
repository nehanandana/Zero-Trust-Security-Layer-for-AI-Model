# mfa_helper.py
import pyotp
import qrcode
from io import BytesIO
import base64
import sqlite3
from typing import Optional, Tuple

class MFAHelper:
    @staticmethod
    def generate_secret() -> str:
        """Generate a new TOTP secret"""
        return pyotp.random_base32()
    
    @staticmethod
    def get_totp_uri(secret: str, username: str, issuer: str = "ZeroTrustAI") -> str:
        """Generate TOTP URI for QR code"""
        return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    
    @staticmethod
    def generate_qr_code(uri: str) -> str:
        """Generate QR code as base64 string for display"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffered = BytesIO()
        # pyrefly: ignore [unexpected-keyword]
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    @staticmethod
    def verify_totp(secret: str, code: str) -> bool:
        """Verify TOTP code"""
        if not secret or not code:
            return False
        # Clean the secret and code
        clean_secret = str(secret).strip().replace(" ", "")
        clean_code = str(code).strip().replace(" ", "")
        
        totp = pyotp.TOTP(clean_secret)
        # valid_window=10 allows for 5 minutes (300 seconds) of clock drift in either direction
        return totp.verify(clean_code, valid_window=10)
    
    @staticmethod
    def get_user_mfa_status(user_id: int) -> Tuple[bool, Optional[str]]:
        """Get user's MFA status and secret"""
        conn = sqlite3.connect('users.db', timeout=20)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT mfa_enabled, mfa_secret FROM users WHERE id = ?",
            (user_id,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return bool(result[0]), result[1]
        return False, None
    
    @staticmethod
    def enable_mfa(user_id: int, secret: str) -> bool:
        """Enable MFA for user"""
        conn = sqlite3.connect('users.db', timeout=20)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE users SET mfa_enabled = 1, mfa_secret = ? WHERE id = ?",
                (secret, user_id)
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error enabling MFA: {e}")
            return False
        finally:
            conn.close()
    
    @staticmethod
    def disable_mfa(user_id: int) -> bool:
        """Disable MFA for user"""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?",
                (user_id,)
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error disabling MFA: {e}")
            return False
        finally:
            conn.close()