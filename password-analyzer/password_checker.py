import re
import hashlib
import requests

def check_strength(password):
    strength_points = 0
    if len(password) >= 8:
        strength_points += 1
    if re.search(r"[A-Z]", password):
        strength_points += 1
    if re.search(r"[a-z]", password):
        strength_points += 1
    if re.search(r"[0-9]", password):
        strength_points += 1
    if re.search(r"[@$!%*?&]", password):
        strength_points += 1

    if strength_points <= 2:
        return "Weak"
    elif strength_points == 3:
        return "Medium"
    else:
        return "Strong"

def check_breach(password):
    sha1_pwd = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5, tail = sha1_pwd[:5], sha1_pwd[5:]
    url = f"https://api.pwnedpasswords.com/range/{first5}"
    res = requests.get(url, timeout=10)
    if res.status_code != 200:
        return "Error checking breach API"
    hashes = (line.split(":") for line in res.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return f"⚠️ This password has appeared in data breaches {count} times!"
    return "✅ This password has NOT been found in breaches."

if __name__ == "__main__":
    pwd = input("Enter a password to check: ")
    print(f"\n🔑 Strength: {check_strength(pwd)}")
    print(check_breach(pwd))
