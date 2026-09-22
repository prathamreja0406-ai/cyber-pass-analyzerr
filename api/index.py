from http.server import BaseHTTPRequestHandler
import json


def analyze_password(password):
    score = 0

    # Length check
    has_length = len(password) >= 8
    if has_length:
        score += 1

    # Uppercase check
    has_upper = False
    for char in password:
        if char.isupper():
            has_upper = True
            break

    if has_upper:
        score += 1

    # Lowercase check
    has_lower = False
    for char in password:
        if char.islower():
            has_lower = True
            break

    if has_lower:
        score += 1

    # Digit check
    has_digit = False
    for char in password:
        if char.isdigit():
            has_digit = True
            break

    if has_digit:
        score += 1

    # Special character check
    special_characters = "!@#$%^&*()-_=+[]{};:'\",.<>?/\\|`~"

    has_special = False
    for char in password:
        if char in special_characters:
            has_special = True
            break

    if has_special:
        score += 1

    # Strength classification
    if score <= 2:
        strength = "WEAK"
    elif score <= 4:
        strength = "MODERATE"
    else:
        strength = "STRONG"

    # Suggestions
    suggestions = []

    if len(password) < 8:
        suggestions.append("Use at least 8 characters.")

    if not has_upper:
        suggestions.append("Add at least one uppercase letter.")

    if not has_lower:
        suggestions.append("Add at least one lowercase letter.")

    if not has_digit:
        suggestions.append("Add at least one number.")

    if not has_special:
        suggestions.append("Add at least one special character.")

    if not suggestions:
        suggestions.append(
            "Good password structure. Avoid reusing it on other accounts."
        )

    return {
        "length": len(password),
        "uppercase": has_upper,
        "lowercase": has_lower,
        "digit": has_digit,
        "special": has_special,
        "score": score,
        "strength": strength,
        "suggestions": suggestions
    }


class handler(BaseHTTPRequestHandler):

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        data = json.loads(body)
        password = data.get("password", "")

        result = analyze_password(password)

        response = json.dumps(result)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        self.wfile.write(response.encode())
