import base64                      # Mã hóa base64 cho Basic Auth
import json                        # Lưu/đọc token ra file JSON
import threading                   # Chạy HTTP callback server song song
import webbrowser                  # Tự mở trình duyệt
from http.server import HTTPServer, BaseHTTPRequestHandler  # Tạo callback endpoint
from urllib.parse import urlencode, urlparse, parse_qs      # Tạo/parse query string
import requests                    # Gửi HTTP request tới DocuSign


# =========================
# CẤU HÌNH DOCUSIGN
# =========================

# OAuth host của DocuSign Developer
AUTH_HOST = "https://account-d.docusign.com"

# Endpoint authorize + token + userinfo
AUTHORIZE_URL = f"{AUTH_HOST}/oauth/auth"
TOKEN_URL = f"{AUTH_HOST}/oauth/token"
USERINFO_URL = f"{AUTH_HOST}/oauth/userinfo"

# Integration Key / Secret Key
CLIENT_ID = "67de494f-93dc-45fb-ae27-08e038247d2c"      # Integration Key (client_id)
CLIENT_SECRET = "17e02092-9d32-4da0-8636-a7bc8632b550"  # Secret Key (client_secret)

# Redirect URI callback cục bộ (phải đăng ký trong Apps and Keys)
CALLBACK_HOST = "localhost"                             # Host callback local
CALLBACK_PORT = 3000                                    # Port callback local
CALLBACK_PATH = "/ds/callback"                          # Path callback
REDIRECT_URI = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}{CALLBACK_PATH}"  # Redirect URI đầy đủ, sử dụng http thay vì https vì thư viện HTTPServer ko có TLS

# Scope: tối thiểu thường cần "signature"; thêm "offline_access" để có refresh token
# DocuSign docs: Authorization Code Grant + refresh token đề cập refresh token usage. :contentReference[oaicite:6]{index=6}
SCOPES = "signature offline_access"

# login_hint: giúp auto điền email trên màn login
LOGIN_HINT_EMAIL = "tvc_adm_it@terumo.co.jp"                    # Email gợi ý cho UI login (optional)

# state: chuỗi do tự đặt để chống CSRF; khi callback về kiểm tra lại
STATE = "my_custom_state_123"

# File lưu token (để lần sau không cần login lại nếu refresh token còn dùng được)
TOKEN_FILE = "docusign_tokens.json"

def build_basic_auth_header(client_id: str, client_secret: str) -> str:
    """
    Trả về header Authorization được yêu cầu theo tài liệu của DocuSign khi yêu cầu Access Token:  
    Authorization: Basic base64(client_id:client_secret)
    """
    raw = f"{client_id}:{client_secret}".encode("utf-8")     # Ghép id:secret -> bytes
    b64 = base64.b64encode(raw).decode("utf-8")              # Base64 bytes -> string
    return f"Basic {b64}"                                    # Ghép prefix "Basic " theo chuẩn

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """
    Handler nhận callback dạng:
      http://localhost:3000/ds/callback?code=...&state=...
    """
    # Biến class để “truyền” kết quả về main thread
    auth_code = None
    auth_state = None
    done_event = None

    def do_GET(self):
        # Parse path + query từ request mà trình duyệt gọi vào
        parsed = urlparse(self.path)

        # Chỉ chấp nhận đúng path callback đã cấu hình
        if parsed.path != CALLBACK_PATH:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Callback Not met")
            return

        # Tách query string thành dict: {"code":[...], "state":[...]}
        qs = parse_qs(parsed.query)

        # Lấy code/state (mỗi key thường chỉ có 1 giá trị)
        OAuthCallbackHandler.auth_code = (qs.get("code") or [None])[0]
        OAuthCallbackHandler.auth_state = (qs.get("state") or [None])[0]

        # Trả HTML để user biết đã xong
        html = (
            b"<html><body><h3>DocuSign OAuth completed.</h3>"
            b"<p>You can close this tab and return to the app.</p></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

        # Báo cho main thread “đã nhận callback”
        if OAuthCallbackHandler.done_event is not None:
            OAuthCallbackHandler.done_event.set()

    def log_message(self, format, *args):
        # Tắt log mặc định cho gọn (tuỳ bạn)
        return


def get_authorization_code_via_browser(timeout_sec: int = 180) -> str:
    """
    - Dựng HTTP server local (HTTP, không TLS)
    - Mở browser tới DocuSign authorize URL
    - Chờ DocuSign redirect về callback để lấy code
    """

    # Reset kết quả cũ (nếu gọi nhiều lần trong 1 process)
    OAuthCallbackHandler.auth_code = None
    OAuthCallbackHandler.auth_state = None

    # Tạo Event để main thread chờ callback
    done = threading.Event()
    OAuthCallbackHandler.done_event = done

    # Tạo server local (HTTP)
    #    Dùng 127.0.0.1 để tránh trường hợp localhost -> ::1 (IPv6) gây lệch nơi listen
    try:
        server = HTTPServer((CALLBACK_HOST, CALLBACK_PORT), OAuthCallbackHandler)
    except OSError as ex:
        # Port bị chiếm hoặc không bind được
        raise RuntimeError(
            f"Cannot start callback server at {CALLBACK_HOST}:{CALLBACK_PORT}. "
            f"Port may be in use or blocked. Details: {ex}"
        )

    # Chạy server “1 request rồi thoát” trong thread phụ
    #    handle_request() sẽ block cho tới khi có 1 request tới
    t = threading.Thread(target=server.handle_request, daemon=True)
    t.start()

    # Build authorize URL đúng chuẩn DocuSign
    query = {
        "response_type": "code",        # bắt buộc: xin authorization code
        "scope": SCOPES,                # ví dụ: "signature offline_access"
        "client_id": CLIENT_ID,         # integration key
        "state": STATE,                 # chống CSRF
        "redirect_uri": REDIRECT_URI
    }
    # login_hint chỉ là optional
    if LOGIN_HINT_EMAIL:
        query["login_hint"] = LOGIN_HINT_EMAIL

    # URL hoàn chỉnh để lấy authorization code
    auth_url = f"{AUTHORIZE_URL}?{urlencode(query)}"

    # in ra để debug nhanh
    print("Listening callback at:", REDIRECT_URI)
    print("Opening browser to:", auth_url)

    # Mở browser để user login/consent
    webbrowser.open(auth_url)

    # Chờ callback hoặc timeout
    ok = done.wait(timeout=timeout_sec)

    # Đóng server (an toàn)
    try:
        server.server_close()
    except:
        pass

    # Nếu không nhận được code thì báo lỗi
    if not ok:
        raise TimeoutError(
            "Timed out waiting for authorization code callback. "
            "Common causes: redirect_uri mismatch, using https while server is http, port blocked, or consent/login not completed."
        )

    # Check state
    if OAuthCallbackHandler.auth_state != STATE:
        raise ValueError(f"State mismatch. Expected={STATE}, got={OAuthCallbackHandler.auth_state}")

    # Check code
    if not OAuthCallbackHandler.auth_code:
        raise ValueError("No authorization code received (missing 'code' query param).")

    return OAuthCallbackHandler.auth_code

def exchange_code_for_tokens(auth_code: str) -> dict:
    """
    Gọi POST /oauth/token để đổi authorization_code -> access_token + refresh_token
    """
    headers = {
        "Authorization": build_basic_auth_header(CLIENT_ID, CLIENT_SECRET)  # Basic base64(id:secret)
    }
    data = {
        "grant_type": "authorization_code",                                  # Chỉ định flow
        "code": auth_code                                                    # Authorization code từ callback
    }
    r = requests.post(TOKEN_URL, headers=headers, data=data, timeout=30)     # Gửi request
    r.raise_for_status()                                                     # Nếu lỗi HTTP -> raise
    return r.json()                                                          # JSON gồm access_token/refresh_token/expires_in...

def refresh_access_token(refresh_token: str) -> dict:
    """
    Gọi POST /oauth/token để xin access token mới từ refresh_token
    """
    headers = {
        "Authorization": build_basic_auth_header(CLIENT_ID, CLIENT_SECRET),  # Basic base64(id:secret)
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "refresh_token",                                       # Chỉ định refresh flow
        "refresh_token": refresh_token,                                      # Refresh token đã lưu
    }
    r = requests.post(TOKEN_URL, headers=headers, data=data, timeout=30)
    r.raise_for_status()
    return r.json()

def get_userinfo(access_token: str) -> dict:
    """
    GET /oauth/userinfo với Bearer token để lấy base_uri, account_id...
    DocuSign docs: user info endpoint. :contentReference[oaicite:10]{index=10}
    """
    headers = {
        "Authorization": f"Bearer {access_token}",                           # Bearer token chuẩn OAuth
    }
    r = requests.get(USERINFO_URL, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()

def pick_default_account(userinfo: dict) -> tuple[str, str]:
    """
    Từ userinfo JSON, chọn account default và trả về:
    (account_id, base_uri)
    """
    accounts = userinfo.get("accounts", [])                                  # Lấy list accounts
    if not accounts:
        raise ValueError("No accounts returned by /oauth/userinfo")

    # Tìm account có is_default = true; nếu không có thì lấy account[0]
    default = next((a for a in accounts if a.get("is_default") is True), accounts[0])

    account_id = default["account_id"]                                       # GUID account id
    base_uri = default["base_uri"]                                           # ví dụ: https://demo.docusign.net
    return account_id, base_uri

def save_tokens(tokens: dict) -> None:
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, ensure_ascii=False, indent=2)                   # Lưu JSON đẹp dễ đọc

def load_tokens() -> dict | None:
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None

if __name__ == "__main__":
    tokens = load_tokens()                                                   # Thử đọc token đã lưu (nếu có)

    if not tokens:
        # Nếu chưa có token, mở browser xin code và đổi token
        code = get_authorization_code_via_browser()
        tokens = exchange_code_for_tokens(code)
        save_tokens(tokens)

    access_token = tokens["access_token"]                                    # Lấy access token
    refresh_token_value = tokens.get("refresh_token")                        # Lấy refresh token (nếu có)

    # Gọi userinfo để lấy base_uri + account_id
    ui = get_userinfo(access_token)
    account_id, base_uri = pick_default_account(ui)

    # basePath để gọi eSignature REST API = base_uri + "/restapi"
    base_path = f"{base_uri}/restapi"

    print("account_id:", account_id)
    print("base_uri:", base_uri)
    print("base_path:", base_path)

    # Ví dụ: refresh token (khi access token hết hạn)
    if refresh_token_value:
        new_tokens = refresh_access_token(refresh_token_value)
        print("new_access_token:", new_tokens["access_token"])
