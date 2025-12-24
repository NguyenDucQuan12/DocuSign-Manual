import base64
import json
import os
import threading
import time
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional, Dict, Any
from urllib.parse import urlencode, urlparse, parse_qs

import requests


@dataclass
class TokenFileModel:
    """
    Model lưu token xuống JSON file để chạy lại không cần login lại (nếu refresh token còn sống).
    """
    access_token: str
    refresh_token: Optional[str]
    expires_in: str  # ISO datetime string, UTC


class DocuSignPdfSenderRest:
    """
    DocuSign eSignature + OAuth Authorization Code Grant:
    - Mở browser lấy authorization code
    - Đổi code lấy access_token/refresh_token
    - Lưu token JSON
    - Tự refresh / tự re-auth khi cần
    - Gửi PDF tạo envelope + ký theo anchor + ngày ký theo /day/ /month/ /year/
    """

    # OAuth host cho Developer/Demo
    AUTH_HOST = "https://account-d.docusign.com"

    # Endpoint authorize (mở browser)
    AUTHORIZE_URL = f"{AUTH_HOST}/oauth/auth"

    # Endpoint token (đổi code / refresh)
    TOKEN_URL = f"{AUTH_HOST}/oauth/token"

    # Endpoint userinfo (lấy base_uri + account_id)
    USERINFO_URL = f"{AUTH_HOST}/oauth/userinfo"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,            # nên dùng http://127.0.0.1:PORT/PATH
        scopes: str,                  # ví dụ: "signature offline_access"
        token_json_path: str,         # nơi lưu token
        login_hint_email: Optional[str] = None,
        state: Optional[str] = None,
        http_timeout_sec: int = 30,
        oauth_callback_timeout_sec: int = 180,
    ):
        self.client_id = client_id                         # Integration Key
        self.client_secret = client_secret                 # Secret Key
        self.redirect_uri = redirect_uri                   # Redirect URI đã đăng ký trong DocuSign
        self.scopes = scopes                               # scope cần xin
        self.login_hint_email = login_hint_email           # optional
        self.state = state or f"state_{int(time.time())}"  # state chống CSRF

        self.token_json_path = token_json_path             # file JSON lưu token

        # ====== Timeouts khi requset ======
        self.http_timeout_sec = http_timeout_sec
        self.oauth_callback_timeout_sec = oauth_callback_timeout_sec

        # ====== HTTP session (tái sử dụng TCP connection) ======
        self.session = requests.Session()

        # ====== Tokens ======
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._access_expires_at: Optional[datetime] = None  # UTC datetime

        # ====== Runtime account info từ /oauth/userinfo ======
        self.account_id: Optional[str] = None
        self.base_uri: Optional[str] = None
        self.base_path: Optional[str] = None  # base_uri + "/restapi"

        # Lock để tránh nhiều luồng refresh/re-auth cùng lúc
        self._lock = threading.Lock()

    def _load_token_file(self) -> Optional[TokenFileModel]:
        """
        Đọc thông tin token được lưu trữ trong dự án
        
        :param self: Description
        :return: Description
        :rtype: TokenFileModel | None
        """
        # Nếu file token chưa tồn tại -> không load
        if not os.path.exists(self.token_json_path):
            return None

        try:
            # Đọc JSON
            with open(self.token_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Nếu không có trường access token thì trả về None
            if not data.get("access_token"):
                return None

            # Trả về các trường cần thiết theo model TokenFileModel
            return TokenFileModel(
                access_token=data.get("access_token"),
                refresh_token=data.get("refresh_token"),
                expires_in=data.get("expires_in"),
            )
        except Exception:
            # JSON hỏng / parse fail -> coi như không có token
            return None

    def _save_token_file(self) -> None:
        """
        Lưu token vào tệp tin json
        
        :param self: không có tham số
        :return: Hàm mặc định trả về None trong mọi trường hợp
        :rtype: None
        """
        # Tạo folder nếu chưa có
        folder = os.path.dirname(self.token_json_path)
        if folder and not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)

        # Chuẩn bị payload JSON
        payload = {
            "access_token": self._access_token,
            "refresh_token": self._refresh_token,
            "expires_in": self._access_expires_at.isoformat() if self._access_expires_at else None,
        }

        # Ghi file JSON (indent cho dễ debug)
        with open(self.token_json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

    def _delete_token_file(self) -> None:
        """
        Xóa tệp chứa token để tránh trường hợp sử dụng lại token hỏng, quá hạn
        
        :param self: Description
        :return: Hàm mặc định trả về None trong mọi trường hợp
        :rtype: None
        """
        # Xoá file token cũ (nếu có) để tránh dùng lại token “hỏng”
        try:
            if os.path.exists(self.token_json_path):
                os.remove(self.token_json_path)
        except Exception:
            # Không raise để tránh làm gãy flow phục hồi
            pass

    def _basic_auth_header(self) -> Dict[str, str]:
        """
        Ghép chuỗi header theo kiểu: Basic base64(client_id:secret_key)
        
        :return: Trả về Athorization đúng kiểu yêu cầu của DocuSign
        :rtype: Dict[str, str]
        """
        # Ghép "client_id:client_secret" theo OAuth spec
        raw = f"{self.client_id}:{self.client_secret}".encode("utf-8")

        # MÃ hóa base64 cho chuỗi
        b64 = base64.b64encode(raw).decode("ascii")

        # Trả header Authorization: Basic <base64>
        return {"Authorization": f"Basic {b64}"}

    def _exchange_code_for_tokens(self, code: str) -> Dict[str, Any]:
        """
        Truy vấn access token từ authorization code lấy được
        
        :param code: authorization code
        :type code: str
        :return: Trả về các thông tin bao gồm access token, refresh token, expired
        :rtype: Dict[str, Any]
        """
        # Body form-urlencoded cho grant_type=authorization_code
        data = {
            "grant_type": "authorization_code",
            "code": code,
        }

        # Gọi tới API nhận access token: POST /oauth/token
        r = self.session.post(
            self.TOKEN_URL,
            headers={**self._basic_auth_header()},
            data=data,
            timeout=self.http_timeout_sec,
        )

        # Nếu HTTP lỗi: ném lỗi kèm body để debug rõ ràng
        if r.status_code >= 400:
            raise RuntimeError(f"Gọi API nhận access token thất bại: HTTP {r.status_code} - {r.text}")

        # Trả về thông tin từ API
        return r.json()

    def _refresh_tokens(self, refresh_token: str) -> Dict[str, Any]:
        """
        Làm mới access token từ refresh token
        
        :param refresh_token: refresh token
        :type refresh_token: str
        :return: Trả về thông tin access token, refresh token và thời gian hết hạn mới
        :rtype: Dict[str, Any]
        """
        # Body form-urlencoded cho grant_type=refresh_token
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        r = self.session.post(
            self.TOKEN_URL,
            headers={**self._basic_auth_header()},
            data=data,
            timeout=self.http_timeout_sec,
        )

        if r.status_code >= 400:
            # DocuSign thường trả error invalid_grant nếu refresh token hết hạn/invalid
            raise RuntimeError(f"Không thể làm mới access token từ refresh token: HTTP {r.status_code} - {r.text}")

        return r.json()

    def _apply_tokens_runtime(self, token_json: Dict[str, Any]) -> None:
        """
        Gán các giá trị token và thười gian hết hạn
        
        :param token_json: json chứa thông tin được trả về khi gọi API lấy token
        :type token_json: Dict[str, Any]
        """
        # Lấy access token
        self._access_token = token_json.get("access_token")

        # Refresh token có thể “rotate” (trả refresh token mới), nếu có thì cập nhật
        new_refresh = token_json.get("refresh_token")
        if new_refresh:
            self._refresh_token = new_refresh

        # expires_in là số giây sống của access token
        expires_in = int(token_json.get("expires_in", 0))

        # Trừ 60 giây buffer để tránh “vừa hết hạn” lúc gọi API
        self._access_expires_at = datetime.now(timezone.utc) + timedelta(seconds=max(expires_in - 60, 0))

    def _load_userinfo(self) -> None:
        """
        Truy vấn thông tin user từ DocuSign
        
        :return: Hàm mặc định trả về None trong mọi trường hợp
        :rtype: None
        """
        # GET /oauth/userinfo để lấy base_uri và account_id
        r = self.session.get(
            self.USERINFO_URL,
            headers={"Authorization": f"Bearer {self._access_token}"},
            timeout=self.http_timeout_sec,
        )

        if r.status_code >= 400:
            raise RuntimeError(f"Không thể truy vấn thông tin người dùng: HTTP {r.status_code} - {r.text}")

        # Lấy thông tin trả về từ API
        ui = r.json()

        # accounts là danh sách tài khoản; chọn account default nếu có
        accounts = ui.get("accounts") or []
        if not accounts:
            raise RuntimeError("Không có tài khoản nào được đăng ký trong DocuSign.")

        acct = next((a for a in accounts if a.get("is_default")), accounts[0])

        # Gán runtime account info
        self.account_id = acct.get("account_id")
        self.base_uri = acct.get("base_uri")

        # base_path dùng cho REST eSign: base_uri + "/restapi"
        self.base_path = f"{self.base_uri}/restapi"

    def _get_authorization_code_via_browser(self) -> str:
        """
        - Dựng HTTP server local tại host/port/path theo redirect_uri
        - Mở browser tới DocuSign authorize URL
        - Chờ callback nhận authorization code
        """

        # Parse redirect_uri thành các phần (scheme, hostname, port, path, v.v.)
        parsed = urlparse(self.redirect_uri)

        # Nếu user cấu hình https -> HTTPServer không nhận được callback (không TLS)
        # Nếu cấu hình https thì ném lỗi nhanh để tránh binding server không hoạt động.
        if parsed.scheme.lower() != "http":
            raise RuntimeError(
                "redirect_uri nên sử dụng http:// vì HTTPServer không có chứng chỉ (TLS) "
                f"Redirect_uri đang sử dụng: {self.redirect_uri}"
            )

        # Lấy các thành phần còn lại của url
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 3000
        callback_path = parsed.path or "/"

        # Event để main thread chờ callback
        done = threading.Event()

        # Biến chia sẻ kết quả giữa handler và main thread
        shared = {"code": None, "state": None, "error": None, "error_desc": None}

        class Handler(BaseHTTPRequestHandler):
            """
            Định nghĩa handler HTTP cho server local;  
            override do_GET để xử lý các api GET request nhận từ DocuSign.
            """
            def do_GET(self):
                """
                HTTPServer khi nhận một HTTP GET sẽ tạo Handler(request, client_address, server) và gọi handler.do_GET()
                
                :param self: Description
                """
                # Parse path/query request callback
                p = urlparse(self.path)

                # Chỉ nhận đúng callback path
                if p.path != callback_path:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not Found")
                    return

                # Parse query string thành dict danh sách; ví dụ ?code=...&state=....
                qs = parse_qs(p.query)

                # DocuSign có thể trả error=access_denied nếu user cancel
                shared["code"] = (qs.get("code") or [None])[0]  # lấy phần tử đầu nếu có, hoặc None nếu không tồn tại
                shared["state"] = (qs.get("state") or [None])[0]
                shared["error"] = (qs.get("error") or [None])[0]
                shared["error_desc"] = (qs.get("error_description") or [None])[0]

                # Trả HTML phản hồi để user biết xong
                body = b"<html><body><h3>DocuSign OAuth completed.</h3><p>You can close this tab.</p></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

                # Set event để main thread tiếp tục
                # Kích hoạt event để main thread (đang chờ) tiếp tục xử lý.
                done.set()

            def log_message(self, format, *args):
                """
                BaseHTTPRequestHandler mặc định in log mỗi request vào stdout/stderr. Override trả về None để tắt log đó (giữ output gọn)
                """
                # Tắt log server cho gọn
                return

        # Start HTTP server; handle 1 request rồi dừng
        try:
            httpd = HTTPServer((host, port), Handler)
        except OSError as ex:
            raise RuntimeError(
                f"Không thể mở kết nối server tại {host}:{port}. Port có thể đang được sử dụng bởi chương trình khác. Chi tiết: {ex}"
            )

        # Chạy server trong thread riêng để tạo một server socket bound vào địa chỉ (host, port) và lưu Handler class để dùng khi có request
        t = threading.Thread(target=httpd.handle_request, daemon=True)
        t.start()

        # Build authorize URL
        query = {
            "response_type": "code",
            "scope": self.scopes,
            "client_id": self.client_id,
            "state": self.state,
            "redirect_uri": self.redirect_uri,
        }
        if self.login_hint_email:
            query["login_hint"] = self.login_hint_email

        # Ghép thành URL hoàn chỉnh để mở trong browser
        auth_url = f"{self.AUTHORIZE_URL}?{urlencode(query)}"

        # Mở browser để user login/consent
        webbrowser.open(auth_url)

        # Chờ callback hoặc timeout
        ok = done.wait(timeout=self.oauth_callback_timeout_sec)

        # Đóng server
        try:
            httpd.server_close()
        except Exception:
            pass

        if not ok:
            raise TimeoutError(
                "Hết thời gian chờ cho quá trình xác thực "
                "Một số nguyên nhân phổ biến: Redirect URL không khớp, người dùng chưa hoàn thành đăng nhập trong thời gian quy định."
            )

        # Nếu user cancel/deny consent
        if shared["error"]:
            raise RuntimeError(f"OAuth error: {shared['error']} - {shared['error_desc']}")

        # Check state chống CSRF
        if shared["state"] != self.state:
            raise RuntimeError(f"State không khớp. Mong chờ ={self.state}, Nhận được={shared['state']}")

        # Check code
        if not shared["code"]:
            raise RuntimeError("Không nhận được authorization code từ url trả về.")

        return shared["code"]

    def initialize(self) -> None:
        """
        Khởi tạo:
        - Nếu có token file: load -> ensure token -> userinfo
        - Nếu refresh fail: re-auth -> userinfo
        """
        # Đọc token từ tệp json
        saved = self._load_token_file()

        if saved:
            # Nạp token từ file
            self._access_token = saved.access_token
            self._refresh_token = saved.refresh_token

            # Parse expires_at UTC
            self._access_expires_at = datetime.fromisoformat(saved.expires_in)

            try:
                # Ensure token (refresh nếu cần)
                self.ensure_access_token()

                # Load userinfo để có base_path/account_id
                self._load_userinfo()
                return
            except Exception:
                # Token file có thể hỏng hoặc refresh token đã chết -> fallback re-auth
                self._delete_token_file()

        # Không có token file hoặc fallback -> re-auth
        self._force_reauth_no_lock()

        # Load userinfo sau khi có token mới
        self._load_userinfo()

    def ensure_access_token(self) -> str:
        """
        Đảm bảo access token hợp lệ:
        - Nếu còn hạn: return
        - Nếu hết hạn: refresh
        - Nếu refresh token chết: re-auth
        """
        with self._lock:
            if not self._access_token:
                raise RuntimeError("Không tìm thấy access token, vui lòng khởi tạo DocuSign Service trước.")

            # Nếu chưa có expires -> coi như hết hạn để an toàn
            if not self._access_expires_at:
                return self._force_reauth_no_lock()

            # Nếu còn hạn -> dùng luôn
            if datetime.now(timezone.utc) < self._access_expires_at:
                return self._access_token

            # Nếu hết hạn -> thử refresh
            if self._refresh_token:
                try:
                    tjson = self._refresh_tokens(self._refresh_token)
                    self._apply_tokens_runtime(tjson)
                    self._save_token_file()
                    return self._access_token
                
                except Exception:
                    # Refresh token chết/hết hạn -> re-auth
                    self._delete_token_file()
                    return self._force_reauth_no_lock()

            # Không có refresh token -> re-auth
            self._delete_token_file()
            return self._force_reauth_no_lock()

    def _force_reauth_no_lock(self) -> str:
        """
        Re-auth:
        - Mở browser xin code
        - Đổi code -> token
        - Lưu file
        """
        # Lấy authorization code
        code = self._get_authorization_code_via_browser()

        # Đổi code lấy token
        tjson = self._exchange_code_for_tokens(code)

        # Apply vào runtime
        self._apply_tokens_runtime(tjson)

        # Lưu file JSON
        self._save_token_file()

        return self._access_token

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        - Kiểm tra access token trước khi gọi
        - Gắn Authorization Bearer
        - Nếu 401: force re-auth và retry 1 lần
        - Nếu 429: retry với backoff (mặc định 2 lần)
        Nếu request có body dạng streaming (file object, generator), các retry có thể thất bại vì body không thể rewind; cần đảm bảo body có thể gửi lại hoặc special-case không retry POST với stream.
        
        :param method: Phương thức gọi API (GET, POST, DELETE, ...)
        :type method: str
        :param url: URL của API
        :type url: str
        :param kwargs: Các tham số bổ sung cho API như data, json, header, params, ...
        :return: Trả về thông tin sau khi gọi API
        :rtype: Response
        """
        # Ensure token trước call
        token = self.ensure_access_token()

        # Lấy tham số headers từ kwargs bằng phương thức pop (lấy xong loại bỏ nó khỏi kwargs), nhận về giá trị hoặc {}
        headers = kwargs.pop("headers", {}) or {}  # đảm bảo nếu truyền headers=None, biến headers sẽ trở thành dict rỗng thay vì None.
        # Tạo header Authorization với phương thức Bearer Token
        headers["Authorization"] = f"Bearer {token}"
        # Đặt lại header đã cập nhật vào kwargs
        kwargs["headers"] = headers

        # Số lần retry khi rate limit
        max_429_retries = 2

        # Gọi lần 1
        r = self.session.request(method, url, timeout=self.http_timeout_sec, **kwargs)

        # Nếu 429: backoff đơn giản dựa trên Retry-After (nếu có)
        while r.status_code == 429 and max_429_retries > 0:
            # Retry-After có thể là giây; nếu không có thì ngủ mặc định 2s
            retry_after = r.headers.get("Retry-After")
            # Lấy thười gian nghỉ giữa lần gọi tiếp theo từ tham số retry_after trả về nếu có, hoặc mặc định là 2s 
            sleep_sec = int(retry_after) if retry_after and retry_after.isdigit() else 2
            time.sleep(sleep_sec)

            max_429_retries -= 1
            r = self.session.request(method, url, timeout=self.http_timeout_sec, **kwargs)

        # Nếu 401: token invalid/revoked -> force re-auth rồi retry 1 lần
        if r.status_code == 401:
            with self._lock:
                # Xoá token file cũ để không dùng lại
                self._delete_token_file()

                # Re-auth để lấy token mới
                self._force_reauth_no_lock()

                # Reload userinfo để chắc chắn base_path/account_id đúng
                self._load_userinfo()

            # Gắn token mới vào header rồi retry, cập nhật headers cũng là cập nhật kwargs vì cùng 1 dict
            headers["Authorization"] = f"Bearer {self._access_token}"
            r = self.session.request(method, url, timeout=self.http_timeout_sec, **kwargs)

        return r

    def send_pdf_for_signature(
        self,
        pdf_path: str,
        signer_name: str,
        signer_email: str,
        email_subject: str = "Please sign this document",
        # Anchor chữ ký
        sig_anchor: str = "/signhere1/",
        # Anchor ngày ký 
        datesigned_source_anchor: Optional[str] = None,
    ) -> str:
        """
        Gửi PDF cho người ký và đặt:
        - SignHere tại sig_anchor
        - Ngày ký theo /day/ /month/ /year/ dựa trên DateSigned + Formula Tabs

        Trả về envelopeId để bạn lưu DB theo dõi.
        """

        # Validate input cơ bản
        if not pdf_path or not os.path.exists(pdf_path):
            raise FileNotFoundError(f"Không tìm thấy tệp tin PDF: {pdf_path}")
        if not signer_email:
            raise ValueError("Địa chỉ email người ký không được bỏ trống")
        if not signer_name:
            raise ValueError("Tên người ký không được bỏ trống")

        # Nếu chưa init base_path/account_id -> init
        if not self.base_path or not self.account_id:
            self.initialize()

        # Đọc tẹp tin PDF
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        if not pdf_bytes:
            raise ValueError("Không thể đọc tệp tin PDF. Hãy thử lại")

        # Chuyển tệp PDF thàng định sạng bytes
        pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")

        # Nếu không truyền anchor riêng cho DateSigned nguồn, dùng day_anchor để “cắm” tại đó
        # (Sau đó ta ẩn field bằng fontColor trắng)
        src_anchor = datesigned_source_anchor

        # Build payload envelope (REST)
        payload = {
            "emailSubject": email_subject,
            "status": "sent",  # sent = gửi email ký ngay; created = nháp
            "documents": [
                {
                    "documentBase64": pdf_b64,
                    "name": os.path.basename(pdf_path),
                    "fileExtension": "pdf",
                    "documentId": "1",
                }
            ],
            "recipients": {
                "signers": [
                    {
                        "name": signer_name,
                        "email": signer_email,
                        "recipientId": "1",
                        "routingOrder": "1",
                        "tabs": {
                            # Tab ký theo anchor
                            "signHereTabs": [
                                {
                                    "anchorString": sig_anchor,
                                    "anchorUnits": "pixels",
                                    "anchorXOffset": "0",
                                    "anchorYOffset": "0",
                                }
                            ],

                            # DateSigned tab “nguồn” (được auto-populate tại thời điểm ký)
                            #    DocuSign: Date Signed tabs tự đổ ngày ký và signer không sửa được
                            #    Ta đặt tabLabel = "dateSigned" để công thức Day/Month/Year tham chiếu.
                            "dateSignedTabs": [
                                {
                                    "tabLabel": "dateSigned",          # label để formula gọi [dateSigned]
                                    "anchorString": src_anchor,        # đặt tại anchor (cùng /day/ để không cần thêm anchor)
                                    "anchorUnits": "pixels",
                                    "anchorXOffset": "0",
                                    "anchorYOffset": "0",

                                    # “Ẩn” bằng cách đặt font màu trắng + font nhỏ (tuỳ PDF nền trắng)
                                    # "fontColor": "white",
                                    # "fontSize": "Size7",
                                }
                            ],
                        },
                    }
                ]
            },
        }

        # Endpoint create envelope:
        url = f"{self.base_path}/v2.1/accounts/{self.account_id}/envelopes"

        # Gọi REST qua wrapper (auto ensure token + retry 401 + backoff 429)
        r = self._request("POST", url, json=payload)

        # Nếu lỗi, ném exception kèm body cho dễ debug
        if r.status_code >= 400:
            raise RuntimeError(f"Create envelope failed: HTTP {r.status_code} - {r.text}")

        # Parse response JSON để lấy envelopeId
        data = r.json()
        envelope_id = data.get("envelopeId")
        if not envelope_id:
            raise RuntimeError(f"Create envelope succeeded but no envelopeId returned: {data}")

        return envelope_id

    def download_document(self, envelope_id: str, document_id: str = "combined") -> bytes:
        """
        Tải tài liệu đã ký:
        - document_id="combined" thường là bản gộp hoàn chỉnh
        """
        if not envelope_id:
            raise ValueError("envelope_id is required")

        # Đảm bảo init
        if not self.base_path or not self.account_id:
            self.initialize()

        # GET documents:
        url = f"{self.base_path}/v2.1/accounts/{self.account_id}/envelopes/{envelope_id}/documents/{document_id}"

        r = self._request("GET", url)

        if r.status_code >= 400:
            raise RuntimeError(f"Download document failed: HTTP {r.status_code} - {r.text}")

        return r.content
if __name__ == "__main__":

    # Khoier tạo dịch vụ DocuSign
    service = DocuSignPdfSenderRest(
        client_id="67de494f-93dc-45fb-ae27-08e038247d2c",        # Integration Key
        client_secret="17e02092-9d32-4da0-8636-a7bc8632b550",    # Secret Key
        redirect_uri="http://localhost:3000/ds/callback",        # phải đăng ký đúng y hệt trong DocuSign Apps & Keys
        scopes="signature",
        token_json_path="./docusign_tokens.json",
        login_hint_email="tvc_adm_it@terumo.co.jp",
    )

    # Gửi PDF cho người ký
    envelope_id = service.send_pdf_for_signature(
        pdf_path=r"src\assets\Mini_Report.pdf",
        signer_name="Nguyễn Đức Quân",
        signer_email="tvc_adm_it@terumo.co.jp",
        sig_anchor="/signhere1/",
        datesigned_source_anchor= "/date/"
    )

    # Lấy id của tài liệu
    print("EnvelopeId:", envelope_id)

    # (Khi hoàn tất) tải file signed (combined)
    # signed_pdf_bytes = service.download_document(envelope_id, document_id="combined")
    # with open(r"C:\Temp\Report_Signed.pdf", "wb") as f:
    #     f.write(signed_pdf_bytes)
