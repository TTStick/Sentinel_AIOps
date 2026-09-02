"""安全工具：口令哈希(PBKDF2-HMAC-SHA256)、凭据加密(Fernet)、令牌生成。"""
import base64
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken

from config import settings

_PBKDF2_ROUNDS = 240_000


# ---------------- 口令 ----------------
def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """返回 (salt_hex, hash_hex)"""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ROUNDS)
    return salt, dk.hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    _, computed = hash_password(password, salt)
    return hmac.compare_digest(computed, expected_hash)


# ---------------- 会话令牌 ----------------
def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


# ---------------- 凭据加密 ----------------
def _fernet() -> Fernet:
    # 从 SECRET_KEY 派生出 32 字节 urlsafe base64 密钥
    digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError):
        return ""
