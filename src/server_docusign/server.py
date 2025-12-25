import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
import requests

@dataclass
class SignerSpec:
    """
    Mô tả 1 người ký trong danh sách gửi envelope.
    """
    name: str                               # Họ tên người ký
    email: str                              # Email người ký
    recipient_id: str                       # Chuỗi id dạng "1","2"...
    routing_order: int                      # Điều khiển tuần tự/song song
    sig_anchor: str = "/signhere/"          # Anchor cho chữ ký
    date_anchor: Optional[str] = "/date/"   # Anchor thời gian ký


# ===================================
# DocuSign REST Service
# ===================================
class DocuSignRestService:
    """
    Service REST thuần để:
    - Dùng access token/refresh token (đã có sẵn) để gọi API
    - Lấy userinfo => base_uri + account_id (basePath)
    - Tạo Connect configuration (webhook)
    - Gửi envelope với PDF + anchor tabs + routingOrder nhiều signer
    """

    def __init__(
        self,
        integration_key: str,
        client_secret: str,
        token_file: str,
        oauth_base: str = "https://account-d.docusign.com",   # Dev environment OAuth base
        timeout_sec: int = 60
    ):
        # Lưu client id/secret để refresh token khi cần
        self.integration_key = integration_key
        self.client_secret = client_secret

        # File JSON để lưu token (access/refresh/expiry + account/base_uri)
        self.token_file = token_file

        # OAuth host (dev)
        self.oauth_base = oauth_base.rstrip("/")

        # Timeout network cho requests
        self.timeout_sec = timeout_sec

        # Nạp token từ file (nếu có)
        self._token: Dict[str, Any] = self._load_token_file()

        # BasePath cho eSignature REST (ví dụ: https://demo.docusign.net/restapi)
        self.base_path: Optional[str] = self._token.get("base_path")

        # AccountId để gọi eSignature API
        self.account_id: Optional[str] = self._token.get("account_id")

    def _load_token_file(self) -> Dict[str, Any]:
        """
        Đọc file token json. Nếu chưa tồn tại thì trả về dict rỗng.
        """
        # Nếu không tồn tại tệp chứa token thì trả về rỗng
        if not os.path.exists(self.token_file):
            return {}
        
        # Đọc thông tin từ tệp json
        with open(self.token_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_token_file(self) -> None:
        """
        Lưu token dict ra file JSON để lần sau dùng lại.
        """
        # Tạo thư mục chứa token
        os.makedirs(os.path.dirname(self.token_file) or ".", exist_ok=True)
        # Lưu thông tin token vào tệp tin
        with open(self.token_file, "w", encoding="utf-8") as f:
            json.dump(self._token, f, ensure_ascii=False, indent=2)

    def ensure_access_token(self) -> str:
        """
        Đảm bảo có access token hợp lệ trước khi gọi bất kỳ API nào.
        - Nếu chưa có access_token => báo lỗi
        - Nếu access_token còn hạn => dùng luôn
        - Nếu sắp hết hạn / hết hạn => refresh bằng refresh_token
        - Sau refresh => cập nhật lại file JSON
        """
        # Lấy token và lưu vào các biến
        access_token = self._token.get("access_token")
        refresh_token = self._token.get("refresh_token")
        expires_at = self._token.get("expires_in")  # epoch seconds

        if not access_token:
            raise RuntimeError(
                "Chưa có access_token trong token_file. "
            )

        # Nếu không có expires_at thì coi như cần refresh để an toàn
        if not expires_at:
            return self._refresh_access_token_or_raise(refresh_token)
        
        # Đổi định dạng thời gian: `expires_at` chuẩn hoá thành datetime
        parsed_expires: Optional[datetime] = None
        if isinstance(expires_at, datetime):
            parsed_expires = expires_at
        elif isinstance(expires_at, (int, float)):
            parsed_expires = datetime.fromtimestamp(float(expires_at), tz=timezone.utc)
        elif isinstance(expires_at, str):
            try:
                parsed_expires = datetime.fromisoformat(expires_at)
            except Exception:
                # fallback: try to parse as float epoch string
                try:
                    parsed_expires = datetime.fromtimestamp(float(expires_at), tz=timezone.utc)
                except Exception:
                    parsed_expires = None

        # Nếu còn hạn -> dùng luôn
        if parsed_expires and datetime.now(timezone.utc) < parsed_expires:
            return access_token

        # Token hết hạn / gần hết hạn => refresh
        return self._refresh_access_token_or_raise(refresh_token)

    def _refresh_access_token_or_raise(self, refresh_token: Optional[str]) -> str:
        """
        Refresh token. Nếu refresh token hết hạn / invalid thì raise rõ ràng.
        """
        if not refresh_token:
            raise RuntimeError(
                "Không có refresh_token để refresh. "
            )

        new_token = self.refresh_token(refresh_token)

        # Cập nhật token store
        self._token.update(new_token)
        self._save_token_file()

        # Refresh xong thì trả access_token mới
        return self._token["access_token"]

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Làm mới access token bằng refresh token
        """
        token_url = f"{self.oauth_base}/oauth/token"

        # Basic auth = base64(client_id:client_secret)
        basic = base64.b64encode(
            f"{self.integration_key}:{self.client_secret}".encode("utf-8")
        ).decode("utf-8")

        headers = {
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        resp = requests.post(token_url, headers=headers, data=data, timeout=self.timeout_sec)

        # Nếu lỗi => ném ra thông tin chi tiết
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Refresh token failed. HTTP {resp.status_code}. Body: {resp.text}"
            )

        payload = resp.json()

        # DocuSign trả về access_token, token_type, expires_in, refresh_token (thường có)
        access_token = payload["access_token"]
        expires_in = int(payload.get("expires_in", 0))
        new_refresh = payload.get("refresh_token", refresh_token)  # có thể rotate refresh token

        # Tính expires_in để check nhanh lần sau, trừ 60 giây buffer để tránh “vừa hết hạn” lúc gọi API
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=max(expires_in - 60, 0))
        return {
            "access_token": access_token,
            "refresh_token": new_refresh,
            "expires_in": str(expires_at),
        }

    # ---------------------------------------
    # 3) Lấy userinfo => base_uri + accountId
    # ---------------------------------------
    def ensure_account_context(self) -> None:
        """
        Đảm bảo đã có base_path + account_id.
        Nếu chưa có, sẽ gọi userinfo:

        GET {oauth_base}/oauth/userinfo
        Authorization: Bearer {access_token}
        """
        # Nếu đã có rồi thì khỏi gọi lại
        if self.base_path and self.account_id:
            return

        # Xác thực token còn hạn hay không
        access_token = self.ensure_access_token()

        # Tạo đường dẫn refresh token và tạo header
        url = f"{self.oauth_base}/oauth/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}

        # Gọi API để lấy thông tin người dùng
        resp = requests.get(url, headers=headers, timeout=self.timeout_sec)
        if resp.status_code >= 400:
            raise RuntimeError(f"Không thể truy vấn thông tin tài khoản. HTTP {resp.status_code}. Body: {resp.text}")

        # Lấy thông tin từ API
        info = resp.json()

        # Lấy trường thông tin account
        accounts = info.get("accounts", [])
        if not accounts:
            raise RuntimeError("Userinfo không có accounts. Kiểm tra scope và quyền của user.")

        default_acc = None
        # Duyệt danh sách account và lấy account default
        for a in accounts:
            if a.get("is_default"):
                default_acc = a
                break
        # Nếu không có account nào được đánh dấu là default thì mặc định lấy account đầu tiên
        if not default_acc:
            default_acc = accounts[0]

        # Gán vào biến account
        self.account_id = default_acc["account_id"]

        # Lấy base URL từ API
        base_uri = default_acc["base_uri"].rstrip("/")

        # base_path cho REST thường là base_uri + "/restapi"
        self.base_path = f"{base_uri}/restapi"

        # Lưu vào token file để lần sau khỏi gọi
        self._token["account_id"] = self.account_id
        self._token["base_path"] = self.base_path
        self._save_token_file()

    def _esign_request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[dict] = None,
        headers_extra: Optional[dict] = None,
        stream: bool = False
    ) -> requests.Response:
        """
        Wrapper gọi eSignature REST:
        - đảm bảo token + account context
        - build URL = base_path + path
        - gắn Authorization header
        - trả về Response (caller tự xử lý content)
        """
        # Đảm bảo base_path + account_id
        self.ensure_account_context()

        # Đảm bảo token còn hạn
        access_token = self.ensure_access_token()

        # Gắn URL và tạo header
        url = f"{self.base_path}{path}"
        headers = {"Authorization": f"Bearer {access_token}"}

        if headers_extra:
            headers.update(headers_extra)

        # Gọi API
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            json=json_body,
            timeout=self.timeout_sec,
            stream=stream,
        )
        return resp

    def create_connect_configuration_json_sim(
        self,
        webhook_url: str,
        *,
        name: str = "My JSON SIM Connect",
        include_hmac: bool = True,
        requires_ack: bool = True,
        enable_log: bool = True,
        all_users: bool = True
    ) -> str:
        """
        Khi một envelope (phong bì ký) phát sinh sự kiện (ví dụ completed), DocuSign sẽ chủ động gửi HTTP POST đến URL webhook được cấu hình, kèm payload mô tả envelope và sự kiện
        cấu hình ở cấp account, áp dụng cho tất cả envelope do account/users gửi), theo hướng JSON SIM (Send Individual Messages) mà DocuSign khuyến nghị. 
        Chỉ cần chạy 1 lần, cấu hình sẽ lưu vào tài khoản, khi nào có sự kiện tự động gửi đến webhook
        """
        # Đảm bảo truy vấn được account id và baseurl để có thể goi api hoàn chỉnh
        self.ensure_account_context()

        # Body theo schema connectCustomConfiguration theo tài liệu từ DocuSign
        body = {
            "configurationType": "custom",                 # Tạo “custom Connect configuration” ở cấp account
            "urlToPublishTo": webhook_url,                 # URL webhook public/https (gửi webhook tới đâu), DocuSign khuyến cáo URL phải TLS-secure (HTTPS)
            "name": name,                                  # Đặt tên cho cấu hình này
            "allUsers": "true" if all_users else "false",  # Áp dụng cho mọi user trong account (mọi envelope do user nào gửi cũng phát webhook).
            "allowEnvelopePublish": "true",                # Nghĩa là DocuSign sẽ thực sự gửi webhook. Nếu tắt, cấu hình tồn tại nhưng không phát event (thường dùng khi migrate/maintenance)
            "enableLog": "true" if enable_log else "false",

            # Theo format JSON SIM (Send Individual Messages) model (Theo khuyến nghị từ DocuSign)
            "deliveryMode": "SIM",
            "eventData": {"version": "restv2.1"},

            # Đăng ký event SIM. Các sự kiện nào thì webhook sẽ kích hoạt
            "events": [
                "envelope-completed",    # Tất cả người nhận đã hoàn thành hành động đc yêu cầu
                "envelope-declined",     # Có người nhận từ chối ký
                "envelope-voided",       # Envelop bị void (hủy) bởi sender/admin     
                # "envelope-sent",       # envelope vừa được gửi
                # recipient-completed,   # từng recipient đã ký xong (hữu ích nếu ký tuần tự nhiều người, cập nhật tiến độ theo từng bước)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
            ],
        }

        # Bật chữ ký HMAC trên request webhook để bạn verify message đến từ DocuSign và không bị sửa nội dung
        if include_hmac:
            body["includeHMAC"] = "true"

        # DocuSign sẽ chờ phản hồi 2xx trong một khoảng thời gian
        # nếu không nhận được 2xx hoặc timeout thì sẽ retry và/hoặc ghi log lỗi delivery. Đây là cơ chế giúp bạn đảm bảo “đã nhận webhook
        # endpoint webhook của bạn phải trả HTTP 2xx nhanh (thường nên ACK ngay, rồi đẩy xử lý nặng sang background/job queue).
        #  Nếu không ACK, DocuSign sẽ coi là delivery fail và retry theo cơ chế của họ
        if requires_ack:
            body["requiresAcknowledgement"] = "true"

        # Gọi API tạo Connect configuration
        path = f"/v2.1/accounts/{self.account_id}/connect"
        resp = self._esign_request("POST", path, json_body=body)

        # Kiểm tra status trả về
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Không thể tạo kết nối tới DocuSign. HTTP {resp.status_code}. Body: {resp.text}"
            )

        # Response thường trả về connectId trong body
        created = resp.json()
        connect_id = created.get("connectId")
        if not connect_id:
            # Tùy môi trường có thể trả schema khác; vẫn trả về raw nếu cần debug
            raise RuntimeError(f"Kết nối thành công, tuy nhiên không nhận được IDConnect. Phản hồi từ DocuSign: {created}")

        return connect_id

    def upsert_connect_configuration_json_sim(
        self,
        webhook_url: str,
        *,
        name: str = "My JSON SIM Connect",
        include_hmac: bool = True,
        requires_ack: bool = True,
        enable_log: bool = True,
        all_users: bool = True,
        events: Optional[List[str]] = None,
        match_by: str = "name_then_url",  # "name_then_url" | "url_then_name"
    ) -> str:
        """
        - Nếu đã tồn tại (match theo name hoặc urlToPublishTo) => UPDATE cấu hình
        - Nếu chưa tồn tại => CREATE cấu hình mới
        - Trả về connectId (ID cấu hình Connect) để lưu DB/config
        """
        #  Đảm bảo đã có account_id + base_path để gọi đúng eSignature REST
        self.ensure_account_context()  

        # danh sách events
        # Nếu không truyền events, dùng mặc định
        if events is None: 
            events = [  # Danh sách mặc định
                "envelope-completed",  # Envelope hoàn tất 
                "envelope-declined",   # Người ký từ chối
                "envelope-voided",     # Envelope bị hủy 
            ]

        # Có thể bổ sung:
        # - "envelope-sent" (theo dõi lúc vừa gửi)
        # - "recipient-completed" (theo dõi từng người ký, hữu ích ký tuần tự)
        # Tên event phụ thuộc format Connect/JSON SIM; JSON SIM thường dùng dạng "envelope-..." :contentReference[oaicite:8]{index=8}

        # Build body cấu hình Connect (custom + JSON SIM)
        body: Dict[str, Any] = {  # Tạo dict JSON body
            "configurationType": "custom",                 # Custom account-level config 
            "urlToPublishTo": webhook_url,                 # URL webhook (public HTTPS) để DocuSign POST tới
            "name": name,                                  # Tên cấu hình để quản trị
            "allUsers": "true" if all_users else "false",  # Áp dụng mọi user trong account (string theo style bạn đang dùng)
            "allowEnvelopePublish": "true",                # Enable “publish” để webhook thực sự chạy
            "enableLog": "true" if enable_log else "false",# Bật log để debug delivery
            "deliveryMode": "SIM",                         # JSON SIM / Send Individual Messages
            "eventData": {"version": "restv2.1"},          # Payload format theo REST v2.1 (thực tế DocuSign support)
            "events": events,                              # Danh sách event sẽ trigger webhook
        }

        # bật HMAC signature để verify webhook
        if include_hmac:  # Nếu muốn bật HMAC
            body["includeHMAC"] = "true"  # DocuSign sẽ gửi signature header để verify

        # bật cơ chế ACK (requiresAcknowledgement)
        if requires_ack:  # Nếu muốn DocuSign yêu cầu server ACK 2xx
            body["requiresAcknowledgement"] = "true"  # DocuSign sẽ chờ phản hồi; fail thì retry 

        list_path = f"/v2.1/accounts/{self.account_id}/connect"  # Endpoint list 
        list_resp = self._esign_request("GET", list_path)        # Gọi REST GET

        # Nếu list lỗi => ném exception chi tiết
        if list_resp.status_code >= 400:  # Check HTTP status
            raise RuntimeError(  # Raise để caller biết rõ nguyên nhân
                f"Không thể tạo cấu hình mới khi không thể truy xuất danh sách cấu hình hiện tại. HTTP {list_resp.status_code}. Body: {list_resp.text}"
            )

        # Parse JSON list response
        list_json = list_resp.json()  # JSON payload trả về

        # Tùy DocuSign version/shape, danh sách có thể nằm dưới key khác nhau
        configs = (  # Ưu tiên các key thường gặp
            list_json.get("configurations") or   # key 1 (một số response dùng)
            []                                   # nếu không có => list rỗng
        )

        # Tìm config “match” theo rule (name/url)
        def _norm(s: Optional[str]) -> str:  # Helper normalize string để so sánh
            return (s or "").strip().lower()  # strip + lower để stable

        want_name = _norm(name)              # Normalize name
        want_url = _norm(webhook_url)        # Normalize url

        matched: Optional[Dict[str, Any]] = None  # Biến giữ config match

        if match_by == "url_then_name":  # Nếu ưu tiên url trước
            # Match theo URL trước
            matched = next(  # Lấy phần tử đầu tiên thỏa điều kiện
                (c for c in configs if _norm(c.get("urlToPublishTo")) == want_url),  # match url
                None  # nếu không có => None
            )
            # Nếu chưa match thì match theo name
            if matched is None:  # Nếu chưa tìm thấy
                matched = next(  # tìm theo name
                    (c for c in configs if _norm(c.get("name")) == want_name),
                    None
                )
        else:
            # Mặc định: match theo name trước
            matched = next(  # Tìm theo name
                (c for c in configs if _norm(c.get("name")) == want_name),
                None
            )
            # Nếu chưa match thì match theo url
            if matched is None:  # Nếu chưa tìm thấy
                matched = next(  # tìm theo url
                    (c for c in configs if _norm(c.get("urlToPublishTo")) == want_url),
                    None
                )

        # Nếu match => UPDATE, nếu không => CREATE
        if matched is not None:
            # Lấy connectId từ config match
            connect_id = matched.get("connectId") or matched.get("id")  # fallback field

            # Nếu không có connectId => không update được
            if not connect_id:  # Kiểm tra connectId
                raise RuntimeError(f"Matched Connect configuration but connectId missing. Matched={matched}")

            # OPTIONAL: so sánh config hiện tại với body mong muốn để tránh update thừa
            # (Giảm rủi ro thay đổi không cần thiết / giảm log noise)
            def _same_field(key: str) -> bool:  # helper so sánh field “string”
                return _norm(str(matched.get(key))) == _norm(str(body.get(key)))

            needs_update = False  # cờ đánh dấu có cần update không

            # So sánh các field quan trọng
            if not _same_field("urlToPublishTo"):  # URL thay đổi
                needs_update = True
            if not _same_field("name"):  # name thay đổi
                needs_update = True
            if not _same_field("allowEnvelopePublish"):  # enable publish thay đổi
                needs_update = True
            if not _same_field("enableLog"):  # logging thay đổi
                needs_update = True
            if not _same_field("deliveryMode"):  # delivery mode thay đổi
                needs_update = True

            # So sánh events theo set (không phụ thuộc thứ tự)
            old_events = matched.get("events") or []  # events hiện tại
            if set(old_events) != set(events):  # khác nhau => cần update
                needs_update = True

            # Nếu caller muốn includeHMAC/requiresAcknowledgement mà config cũ khác => update
            if include_hmac:
                if _norm(str(matched.get("includeHMAC"))) != _norm("true"):
                    needs_update = True
            if requires_ack:
                if _norm(str(matched.get("requiresAcknowledgement"))) != _norm("true"):
                    needs_update = True

            # Nếu không cần update thì trả connectId luôn
            if not needs_update:  # Không cần update
                return str(connect_id)  # Trả về connectId (ID cấu hình Connect)

            # Endpoint update: PUT /v2.1/accounts/{accountId}/connect/{connectId}
            update_path = f"/v2.1/accounts/{self.account_id}/connect/{connect_id}"  # URL update
            update_resp = self._esign_request("PUT", update_path, json_body=body)   # Gọi PUT update

            # Nếu update lỗi => ném exception chi tiết
            if update_resp.status_code >= 400:  # Check status
                raise RuntimeError(
                    f"Cập nhật cấu hình kết nối thất bại. HTTP {update_resp.status_code}. Body: {update_resp.text}"
                )

            # Update thành công => trả connectId cũ (vì config update vẫn cùng ID)
            return str(connect_id)

        else:
            # CREATE mới: POST /v2.1/accounts/{accountId}/connect
            create_path = f"/v2.1/accounts/{self.account_id}/connect"  # URL create
            create_resp = self._esign_request("POST", create_path, json_body=body)  # Gọi POST create

            # Nếu create lỗi => ném exception chi tiết
            if create_resp.status_code >= 400:  # Check status
                raise RuntimeError(
                    f"Tạo cấu hình kết nối mới thất bại. HTTP {create_resp.status_code}. Body: {create_resp.text}"
                )

            # Parse response để lấy connectId
            created = create_resp.json()  # JSON response
            connect_id = created.get("connectId")  # connectId thường có trong body :contentReference[oaicite:19]{index=19}

            # Nếu không có connectId => raise để bạn debug response
            if not connect_id:  # Validate connectId
                raise RuntimeError(f"Kết nối mới đã được tạo nhưng không trả về ID connect. Phản hồi từ DocuSign: {created}")

            # Trả connectId của config mới tạo
            return str(connect_id)

    # ==========================================================
    # Gửi envelope: PDF + nhiều signer + anchor + ngày ký
    # ==========================================================
    def send_pdf_for_signing(
        self,
        pdf_bytes: bytes,
        *,
        document_name: str,
        email_subject: str,
        signers: List[SignerSpec],
        status: str = "sent"
    ) -> str:
        """
        Tạo envelope với tài liệu PDF + recipients + tabs theo anchor.

        Endpoint tạo envelope (eSignature):
        POST /v2.1/accounts/{accountId}/envelopes

        routingOrder:
          - song song: nhiều signer cùng routingOrder
          - tuần tự: routingOrder tăng dần
        """
        # Đảm bảo có baseurrl và account id
        self.ensure_account_context()

        # Encode PDF bytes sang base64 để nhét vào documentBase64 (Yêu cầu từ DocuSign)
        doc_b64 = base64.b64encode(pdf_bytes).decode("utf-8")

        # Khai báo documents
        documents = [{
            "documentBase64": doc_b64,
            "name": document_name,
            "fileExtension": "pdf",
            "documentId": "1",   # bạn có thể chọn "1" cho doc đầu
        }]

        # Build recipients.signers
        # Mỗi signer có tabs riêng, gắn anchor khác nhau nếu muốn.
        recipient_signers = []
        for s in signers:
            # SignHere tab theo anchor chữ ký
            sign_here_tabs = [{
                "anchorString": s.sig_anchor,          # anchor chữ ký
                "anchorUnits": "pixels",
                "anchorXOffset": "0",
                "anchorYOffset": "0",
                "documentId": "1",
                # "pageNumber": "1",                      # anchor thường không cần pageNumber
            }]

            # DateSigned tab: DocuSign tự fill ngày ký.
            date_signed_tabs = [{
                "anchorString": s.date_anchor,          # cần đặt anchor này trong PDF
                "anchorUnits": "pixels",
                "anchorXOffset": "0",
                "anchorYOffset": "0",
                "documentId": "1",
                # "pageNumber": "1",
            }]

            # Gắn 2 tab này với nhau
            tabs = {
                "signHereTabs": sign_here_tabs,
                "dateSignedTabs": date_signed_tabs,
            }

            # Thêm vào recipient_signers
            recipient_signers.append({
                "name": s.name,
                "email": s.email,
                "recipientId": s.recipient_id,
                "routingOrder": str(s.routing_order),  # DocuSign thường nhận string
                "tabs": tabs,
            })

        recipients = {"signers": recipient_signers}

        # EnvelopeDefinition
        envelope_definition = {
            "emailSubject": email_subject,
            "documents": documents,
            "recipients": recipients,
            "status": status,  # "sent" gửi ngay; "created" lưu nháp
        }

        # POST create envelope
        path = f"/v2.1/accounts/{self.account_id}/envelopes"
        resp = self._esign_request("POST", path, json_body=envelope_definition)

        if resp.status_code >= 400:
            raise RuntimeError(
                f"Tạo envelope thất bại. HTTP {resp.status_code}. Body: {resp.text}"
            )
        
        # Nhận thông tin từ api trả về
        data = resp.json()
        # Lấy thông tin envelop để có thể tải tài liệu sau khi hoàn thành
        envelope_id = data.get("envelopeId")

        # Nếu không nhận được id thì có lỗi xảy ra
        if not envelope_id:
            raise RuntimeError(f"Không thể nhận lại giá trị id của envelop. Thông báo từ DocuSign: {data}")

        return envelope_id

    def download_completed_combined_pdf(
        self,
        envelope_id: str,
        *,
        include_certificate: bool = True
    ) -> bytes:
        """
        Tải "combined" PDF (gộp tất cả documents).
        Tham số certificate=true có thể dùng để kèm Certificate of Completion (tùy account settings)
        """
        doc_id = "combined"
        path = f"/v2.1/accounts/{self.account_id}/envelopes/{envelope_id}/documents/{doc_id}"

        # Query param certificate=true/false (DocuSign hỗ trợ với combined)
        # requests.request trong _esign_request không nhận params hiện tại; để đơn giản, ta nối query vào path
        cert_value = "true" if include_certificate else "false"
        path_with_qs = f"{path}?certificate={cert_value}"

        resp = self._esign_request("GET", path_with_qs, stream=True)

        if resp.status_code >= 400:
            raise RuntimeError(
                f"Tải về tài liệu thất bại. HTTP {resp.status_code}. Body: {resp.text}"
            )

        return resp.content

if __name__ == "__main__":

    svc = DocuSignRestService(
        integration_key="67de494f-93dc-45fb-ae27-08e038247d2c",
        client_secret="17e02092-9d32-4da0-8636-a7bc8632b550",
        token_file="docusign_tokens.json",
    )

    # (A) Tạo Connect config (chạy 1 lần)
    # connect_id = svc.create_connect_configuration_json_sim(
    #     webhook_url="https://your-public-domain.com/webhooks/docusign",
    #     name="My Connect JSON SIM",
    #     include_hmac=True,
    #     requires_ack=True,
    #     enable_log=True,
    # )

    connect_id = svc.upsert_connect_configuration_json_sim(
        webhook_url="https://your-public-domain.com/webhooks/docusign",
        name="My Connect JSON SIM",
        include_hmac=True,
        requires_ack=True,
        enable_log=True,
        all_users=True,
        events=[
            "envelope-completed",
            "envelope-declined",
            "envelope-voided",
            # Nếu muốn theo dõi tiến độ từng người ký:
            # "recipient-completed",
        ],
    )

    print("Connect config id:", connect_id)

    # # Gửi PDF
    # with open("src\\assets\\Mini_Report.pdf", "rb") as f:
    #     pdf_bytes = f.read()

    # # Tuần tự: 1 -> 2
    # signers_sequential = [
    #     SignerSpec(
    #         name="Nguyễn Phương Hà",
    #         email="tvc_adm_it2@terumo.co.jp",
    #         recipient_id="1",
    #         routing_order=1,
    #         sig_anchor="/signhere1/",
    #         date_anchor="/date/",
    #     ),
    #     SignerSpec(
    #         name="Nguyễn Đức Quân",
    #         email="tvc_Adm_it@terumo.co.jp",
    #         recipient_id="2",
    #         routing_order=2,
    #         sig_anchor="/signhere2/",
    #         date_anchor="/date/",
    #     ),
    # ]

    # envelope_id = svc.send_pdf_for_signing(
    #     pdf_bytes,
    #     document_name="Report.pdf",
    #     email_subject="Bạn có tài liệu cần ký",
    #     signers=signers_sequential,
    #     status="sent",
    # )

    # print("EnvelopeId:", envelope_id)

    # Song song: cả 2 routing_order=1
    # signers_parallel = [
    #     SignerSpec(name="Signer C", email="c@example.com", recipient_id="1", routing_order=1, sig_anchor="/sigC/"),
    #     SignerSpec(name="Signer D", email="d@example.com", recipient_id="2", routing_order=1, sig_anchor="/sigD/"),
    # ]