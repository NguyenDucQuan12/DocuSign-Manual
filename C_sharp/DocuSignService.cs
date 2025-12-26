using System;
using System.Collections.Generic;
using System.Diagnostics;                       // Process.Start để mở trình duyệt
using System.IO;                                // File đọc/ghi JSON token
using System.Linq;
using System.Net;                               // HttpListener để nhận callback
using System.Net.Http;                          // HttpClient để gọi /oauth/token, /oauth/userinfo
using System.Net.Http.Headers;                  // AuthenticationHeaderValue (Bearer/Basic)
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;                          // JSON serialize/deserialize

// DocuSign eSign SDK: dùng để tạo envelope và gọi eSignature API, tải thư viện DocuSign.eSign từ NuGet
using DocuSign.eSign.Api;
using DocuSign.eSign.Client;
using DocuSign.eSign.Model;

/******************************************************************************/
// THAM KHẢO HƯỚNG DẪN LẤY ACCESS TOKEN VÀ REFRESH TOKEN TỪ DOCUSIGN
// https://developers.docusign.com/platform/auth/public-authcode-get-token/
/*******************************************************************************/


public sealed class DocuSignService
{
    // =========================
    // Các endpoint của DocuSign OAuth
    // =========================

    // Host OAuth của DocuSign để xin code, đổi token, và userinfo
    private const string AuthHost = "https://account-d.docusign.com";

    // Endpoint authorize (mở browser)
    private static readonly Uri AuthorizeUri = new Uri($"{AuthHost}/oauth/auth");

    // Endpoint token (đổi code / refresh token)
    private static readonly Uri TokenUri = new Uri($"{AuthHost}/oauth/token");

    // Endpoint userinfo (lấy base_uri + account_id)
    private static readonly Uri UserInfoUri = new Uri($"{AuthHost}/oauth/userinfo");

    // =========================
    // CÁC THÔNG TIN TRONG MỤC APPS AND INTEGRATION KEYS
    // =========================

    // Integration Key (client_id) của DocuSign app
    private readonly string _clientId;

    // Secret Key (client_secret) của DocuSign app (Chỉ hiển thị 1 lần, khi tạo nhớ lưu lại)
    private readonly string _clientSecret;

    // Redirect URI đăng ký trong DocuSign Apps and Keys
    private readonly string _redirectUri;

    // Scope OAuth: tối thiểu cần "signature"; muốn refresh token thì phải có "offline_access"
    // Ví dụ: "signature offline_access"
    private readonly string _scopes;

    // login_hint (email) để gợi ý tài khoản trên UI login
    private readonly string _loginHintEmail;

    // state dùng chống CSRF (tùy chọn nhưng khuyến nghị)
    private readonly string _state;

    // =========================
    // TOKEN STORAGE (JSON FILE)
    // =========================

    // File path để lưu token JSON
    private readonly string _tokenJsonPath;

    // =========================
    // HTTP + LOCK
    // =========================

    // HttpClient dùng chung (khuyến nghị dùng lại, không tạo mới liên tục)
    private readonly HttpClient _http;

    // Lock để tránh 2 luồng refresh token cùng lúc (race condition)
    private readonly SemaphoreSlim _tokenLock = new SemaphoreSlim(1, 1);

    // =========================
    // TRẠNG THÁI RUNTIME: token + account + basePath
    // =========================

    // Access token hiện tại (dùng cho mọi API)
    private string _accessToken;

    // Refresh token hiện tại (dùng xin access token mới khi access token hết hạn, ko cần login)
    private string _refreshToken;

    // Thời điểm access token hết hạn (UTC)
    private DateTime _accessTokenExpiresAtUtc;

    // AccountId lấy từ /oauth/userinfo (GUID)
    public string AccountId { get; private set; }

    // base_uri lấy từ /oauth/userinfo (vd: https://demo.docusign.net), baseUri để gọi api tùy vào tài khoản là test hay là tài khoản thực tế
    public string BaseUri { get; private set; }

    // BasePath dùng cho DocuSignClient (vd: https://demo.docusign.net/restapi)
    public string BasePath { get; private set; }

    public DocuSignService(
        string clientId,
        string clientSecret,
        string redirectUri,
        string scopes,
        string tokenJsonPath,
        string loginHintEmail = null,
        string state = null,
        HttpClient httpClient = null)
    {
        // Gán Integration Key
        _clientId = clientId ?? throw new ArgumentNullException(nameof(clientId));

        // Gán Secret Key
        _clientSecret = clientSecret ?? throw new ArgumentNullException(nameof(clientSecret));

        // Gán Redirect URI (phải khớp với cấu hình trong. DocuSign Apps and Keys)
        _redirectUri = redirectUri ?? throw new ArgumentNullException(nameof(redirectUri));

        // Gán scope
        _scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));

        // Gán nơi lưu token JSON
        _tokenJsonPath = tokenJsonPath ?? throw new ArgumentNullException(nameof(tokenJsonPath));

        // Gán login_hint nếu có
        _loginHintEmail = loginHintEmail;

        // Nếu không truyền state, tự sinh 1 state ngẫu nhiên
        _state = string.IsNullOrWhiteSpace(state) ? ("state_" + Guid.NewGuid().ToString("N")) : state;

        // Dùng HttpClient truyền vào, hoặc tự tạo mới nếu null
        _http = httpClient ?? new HttpClient();
    }

    /// <summary>
    /// Khởi tạo service:
    /// - Nếu đã có token JSON: tải token, thử userinfo; nếu token gần hết hạn thì refresh
    /// - Nếu chưa có token JSON: mở browser xin authorization code -> đổi token -> lưu JSON -> userinfo
    /// </summary>
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await _tokenLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Bước 1: thử load token từ JSON
            var saved = LoadTokenFromJsonFile();

            if (saved != null)
            {
                // Nạp token từ file vào RAM
                _accessToken = saved.AccessToken;
                _refreshToken = saved.RefreshToken;
                _accessTokenExpiresAtUtc = saved.AccessTokenExpiresAtUtc;

                try
                {
                    // Bước 2: đảm bảo access token hợp lệ (refresh nếu cần)
                    await EnsureAccessToken_NoLockAsync(ct).ConfigureAwait(false);

                    // Bước 3: lấy userinfo để có base_uri/account_id/basePath
                    await LoadUserInfo_NoLockAsync(ct).ConfigureAwait(false);

                    return; // OK
                }
                catch (HttpRequestException ex) when (IsRefreshTokenInvalid(ex))
                {
                    // Refresh token đã chết
                    DeleteTokenFileIfExists();     // xóa token cũ để tránh dùng lại
                    // Khởi tạo mới access token bằng re-auth và lấy các thông tin cần thiết
                    await ReAuthorizeAndSaveAsync(ct).ConfigureAwait(false);
                    await LoadUserInfo_NoLockAsync(ct).ConfigureAwait(false);
                    return;
                }
            }

            // Nếu không có token file -> re-auth luôn
            await ReAuthorizeAndSaveAsync(ct).ConfigureAwait(false);
            await LoadUserInfo_NoLockAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    /// <summary>
    /// Kiểm tra lỗi HttpRequestException có phải do refresh token invalid hay không
    /// Để thu hồi token file và yêu cầu re-auth nếu cần
    /// </summary>
    /// <param name="ex"></param>
    /// <returns></returns>
    private static bool IsRefreshTokenInvalid(HttpRequestException ex)
    {
        // Vì ta ném HttpRequestException kèm "Body: {json}" trong message,
        var msg = ex.Message ?? "";

        // invalid_grant là lỗi OAuth phổ biến khi refresh token invalid/expired/used/revoked
        if (msg.IndexOf("invalid_grant", StringComparison.OrdinalIgnoreCase) >= 0)
            return true;

        // Một số response sẽ ghi rõ refresh token invalid
        if (msg.IndexOf("refresh_token", StringComparison.OrdinalIgnoreCase) >= 0 &&
            msg.IndexOf("invalid", StringComparison.OrdinalIgnoreCase) >= 0)
            return true;

        return false;
    }

    /// <summary>
    /// Xóa file token JSON nếu tồn tại
    /// </summary>
    private void DeleteTokenFileIfExists()
    {
        try
        {
            if (File.Exists(_tokenJsonPath))
                File.Delete(_tokenJsonPath);
        }
        catch
        {
            // Không throw ở đây để tránh làm “gãy” luồng khôi phục.
            // Nếu xóa fail (permission), vẫn có thể re-auth và lưu file mới (có thể fail tiếp).
        }
    }

    /// <summary>
    /// Yêu cầu re-authorization (mở browser xin code), tiến hành lấy access token từ code vừa có và lưu token mới
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    private async Task ReAuthorizeAndSaveAsync(CancellationToken ct)
    {
        // Mở browser xin authorization code
        string code = await GetAuthorizationCodeViaBrowserAsync(ct).ConfigureAwait(false);

        // Đổi code -> token mới
        TokenResponse tokens = await ExchangeCodeForTokensAsync(code, ct).ConfigureAwait(false);

        // Áp tokens vào runtime
        ApplyTokensToRuntime(tokens);

        // Lưu file JSON
        SaveTokenToJsonFile();
    }

    /// <summary>
    /// Đảm bảo access token còn hạn.
    /// Gọi trước mọi thao tác gọi eSign API.
    /// </summary>
    public async Task<string> EnsureAccessTokenAsync(CancellationToken ct = default)
    {
        // Dùng lock để tránh refresh token đồng thời
        await _tokenLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await EnsureAccessToken_NoLockAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    /// <summary>
    /// Gửi 1 PDF (bytes) cho 1 người ký qua email, đặt vị trí ký theo anchor string.
    /// Trả về EnvelopeId để lưu DB theo dõi trạng thái.
    /// </summary>
    public async Task<string> SendPdfForSignatureViaEmailAsync(
        byte[] pdfBytes,
        string documentName,
        string signerName,
        string signerEmail,
        string anchorString,
        CancellationToken ct = default)
    {
        // Đảm bảo service đã init (có BasePath/AccountId và token)
        if (string.IsNullOrWhiteSpace(BasePath) || string.IsNullOrWhiteSpace(AccountId))
            throw new InvalidOperationException("Docusign chưa được khởi tạo, hoặc khởi tạo thất bại. Vui lòng khởi động lại ứng dụng.");

        // Đảm bảo access token còn hạn (refresh nếu cần)
        string token = await EnsureAccessTokenAsync(ct).ConfigureAwait(false);

        // Validate input PDF
        if (pdfBytes == null || pdfBytes.Length == 0)
            throw new ArgumentException("Báo cáo có kích thước rỗng. Không thể gửi tới người phê duyệt", nameof(pdfBytes));

        // Validate signer info
        if (string.IsNullOrWhiteSpace(signerEmail))
            throw new ArgumentException("Thiếu địa chỉ email người phê duyệt", nameof(signerEmail));
        if (string.IsNullOrWhiteSpace(signerName))
            throw new ArgumentException("Thông tin người phê duyệt thiếu, chưa cung cấp họ tên người phê duyệt.", nameof(signerName));

        // Validate anchor
        if (string.IsNullOrWhiteSpace(anchorString))
            throw new ArgumentException("Vị trí ký chưa được cung cấp. Tham khảo cách đặt tham chiếu đến địa chỉ ký hợp lệ.", nameof(anchorString));

        // Dựng EnvelopeDefinition (payload) theo DocuSign SDK
        EnvelopeDefinition env = MakeEnvelopeFromPdfBytes(
            pdfBytes: pdfBytes,
            documentName: documentName ?? "Report.pdf",
            signerName: signerName,
            signerEmail: signerEmail,
            anchorString: anchorString,
            envStatus: "sent" // "sent" = gửi email ký ngay; "created" = nháp
        );

        // Tạo DocuSignClient với BasePath (vd: https://demo.docusign.net/restapi)
        var client = new DocuSignClient(BasePath);

        // Gắn header Authorization: Bearer {access_token}
        client.Configuration.DefaultHeader["Authorization"] = "Bearer " + token;

        // Tạo EnvelopesApi từ client
        var envelopesApi = new EnvelopesApi(client);

        // Gọi CreateEnvelope (SDK sync) nên bọc Task.Run để không block UI thread
        //     (Nếu bạn gọi trong background thread thì có thể gọi trực tiếp)
        var envelopeId = await Task.Run(() =>
        {
            // CreateEnvelopeWithHttpInfo cho phép lấy headers (rate limit) nếu cần
            var result = envelopesApi.CreateEnvelopeWithHttpInfo(AccountId, env);

            // Trả về EnvelopeId để bạn lưu DB / hiển thị
            return result.Data.EnvelopeId;
        }, ct).ConfigureAwait(false);

        return envelopeId;
    }

    /// <summary>
    /// Tạo envelop theo mâu của DocuSign
    /// </summary>
    /// <param name="pdfBytes"></param>
    /// <param name="documentName"></param>
    /// <param name="signerName"></param>
    /// <param name="signerEmail"></param>
    /// <param name="anchorString"></param>
    /// <param name="envStatus"></param>
    /// <returns></returns>
    private static EnvelopeDefinition MakeEnvelopeFromPdfBytes(
        byte[] pdfBytes,
        string documentName,
        string signerName,
        string signerEmail,
        string anchorString,
        string envStatus)
    {
        // Tạo envelope definition (payload gốc)
        var env = new EnvelopeDefinition
        {
            // Subject email gửi cho người ký
            EmailSubject = "Vui lòng ký tài liệu",
            // Status: "sent" để gửi ngay, "created" để tạo nháp
            Status = envStatus
        };

        // Tạo document: PDF bytes -> base64 string
        var doc = new Document
        {
            // Base64 nội dung PDF
            DocumentBase64 = Convert.ToBase64String(pdfBytes),
            // Tên hiển thị tài liệu trên DocuSign
            Name = documentName,
            // Đuôi file
            FileExtension = "pdf",
            // DocumentId là chuỗi; nếu có nhiều tài liệu tăng "2", "3", ...
            DocumentId = "1"
        };

        // Gắn documents vào envelope
        env.Documents = new List<Document> { doc };

        // Tạo signer (người ký)
        var signer = new Signer
        {
            // Email người ký
            Email = signerEmail,
            // Tên người ký
            Name = signerName,
            // RecipientId là chuỗi; dùng để tham chiếu
            RecipientId = "1",
            // RoutingOrder: "1" nghĩa là ký bước 1 (nếu nhiều người ký theo thứ tự)
            RoutingOrder = "1"
        };

        // AnchorString phải đúng chuỗi chèn trong PDF, ví dụ "/sig1/"
        var signHere = new SignHere
        {
            AnchorString = anchorString,   // chuỗi neo trong PDF
            AnchorUnits = "pixels",        // đơn vị offset
            AnchorXOffset = "0",           // lệch X (px) nếu cần
            AnchorYOffset = "0"            // lệch Y (px) nếu cần
        };

        var dateSign = new DateSigned
        {
            AnchorString = "/date/",
            AnchorUnits = "pixels",
            AnchorXOffset = "0",
            AnchorYOffset = "0"
        };

        // Gắn tabs vào signer
        signer.Tabs = new Tabs
        {
            // SignHereTabs: danh sách vị trí ký
            SignHereTabs = new List<SignHere> { signHere },
            DateSignedTabs = new List<DateSigned> { dateSign }
        };

        // Gắn recipients vào envelope
        env.Recipients = new Recipients
        {
            // Danh sách signers
            Signers = new List<Signer> { signer }
        };

        return env;
    }

    /// <summary>
    /// Kiểm tra và đảm bảo access token còn hạn.
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    private async Task<string> EnsureAccessToken_NoLockAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_accessToken))
            throw new InvalidOperationException("No access token. Call InitializeAsync() first.");

        // Nếu còn hạn thì dùng luôn
        if (DateTime.UtcNow < _accessTokenExpiresAtUtc)
            return _accessToken;

        // Nếu hết hạn mà không có refresh token -> buộc re-auth
        if (string.IsNullOrWhiteSpace(_refreshToken))
        {
            // Xóa token file cũ (nếu có) và re-auth
            DeleteTokenFileIfExists();
            await ReAuthorizeAndSaveAsync(ct).ConfigureAwait(false);
            return _accessToken;
        }

        try
        {
            // Thử refresh token
            TokenResponse newTokens = await RefreshAccessTokenAsync(_refreshToken, ct).ConfigureAwait(false);

            // Cập nhật tokens
            ApplyTokensToRuntime(newTokens);

            // Lưu lại JSON
            SaveTokenToJsonFile();

            return _accessToken;
        }
        catch (HttpRequestException ex) when (IsRefreshTokenInvalid(ex))
        {
            // Refresh token đã chết -> re-auth
            DeleteTokenFileIfExists();
            await ReAuthorizeAndSaveAsync(ct).ConfigureAwait(false);
            return _accessToken;
        }
    }

    /// <summary>
    /// Gắn access token mới vào biến runtime
    /// </summary>
    /// <param name="tokens"></param>
    private void ApplyTokensToRuntime(TokenResponse tokens)
    {
        // Gán access token mới
        _accessToken = tokens.AccessToken;

        // Một số trường hợp API trả refresh token mới; nếu có thì cập nhật
        if (!string.IsNullOrWhiteSpace(tokens.RefreshToken))
            _refreshToken = tokens.RefreshToken;

        // expires_in là số giây sống; trừ 60s buffer để tránh hết hạn đúng lúc gọi API
        _accessTokenExpiresAtUtc = DateTime.UtcNow.AddSeconds(tokens.ExpiresIn - 60);
    }

    /// <summary>
    /// Lấy userinfo từ /oauth/userinfo để có accountId, baseUri, basePath
    /// </summary>
    /// <param name="ct"></param>
    /// <returns></returns>
    /// <exception cref="HttpRequestException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    private async Task LoadUserInfo_NoLockAsync(CancellationToken ct)
    {
        // Tạo request GET /oauth/userinfo
        using (var req = new HttpRequestMessage(HttpMethod.Get, UserInfoUri))
        {
            // Authorization: Bearer {access_token}
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);

            // Gửi request
            using (var resp = await _http.SendAsync(req, ct).ConfigureAwait(false))
            {
                // Đọc JSON body
                string json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);

                // Nếu lỗi, ném exception kèm body để dễ debug
                if (!resp.IsSuccessStatusCode)
                    throw new HttpRequestException($"UserInfo failed. HTTP {(int)resp.StatusCode}. Body: {json}");

                // Parse JSON -> UserInfoResponse
                var ui = JsonConvert.DeserializeObject<UserInfoResponse>(json);

                // Lấy accounts
                var accounts = ui?.Accounts ?? new List<UserInfoAccount>();
                if (accounts.Count == 0)
                    throw new InvalidOperationException("No accounts returned by /oauth/userinfo.");

                // Chọn default account (is_default==true), nếu không có thì lấy account đầu
                var acct = accounts.FirstOrDefault(a => a.IsDefault) ?? accounts[0];

                // Gán AccountId theo mẫu bạn đưa
                AccountId = acct.AccountId;

                // Gán BaseUri theo mẫu bạn đưa (vd: https://demo.docusign.net)
                BaseUri = acct.BaseUri;

                // Ghép BasePath dùng cho các API eSignature: base_uri + "/restapi"
                BasePath = $"{BaseUri}/restapi";
            }
        }
    }
    private async Task<string> GetAuthorizationCodeViaBrowserAsync(CancellationToken ct)
    {
        // Tạo HttpListener để lắng nghe callback từ redirect_uri
        var listener = new HttpListener();

        // HttpListener yêu cầu prefix kết thúc bằng dấu "/"
        // Nếu redirectUri là "http://localhost:8080/callback" -> prefix phải là "http://localhost:8080/callback/"
        string prefix = _redirectUri.EndsWith("/") ? _redirectUri : _redirectUri + "/";

        // Add prefix vào listener
        listener.Prefixes.Add(prefix);

        // Start lắng nghe
        listener.Start();

        try
        {
            // Build authorize URL theo đúng format DocuSign:
            // /oauth/auth?response_type=code&scope=...&client_id=...&state=...&redirect_uri=...&login_hint=...
            var query = new Dictionary<string, string>
            {
                ["response_type"] = "code",                 // bắt buộc: xin authorization code
                ["scope"] = _scopes,                        // scope bạn yêu cầu
                ["client_id"] = _clientId,                  // integration key
                ["state"] = _state,                         // state chống CSRF
                ["redirect_uri"] = _redirectUri.TrimEnd('/')// redirect_uri phải khớp chính xác cấu hình
            };

            // Nếu có login_hint thì thêm
            if (!string.IsNullOrWhiteSpace(_loginHintEmail))
                query["login_hint"] = _loginHintEmail;

            // Ghép query string
            string authUrl = $"{AuthorizeUri}?{ToQueryString(query)}";

            // Mở browser mặc định tới authUrl để user login/consent
            // Lưu ý: Authorization Code Grant luôn cần UI trình duyệt để login/consent
            Process.Start(authUrl);

            // Chờ callback tới (GET /callback?code=...&state=...)
            // Vì HttpListener.GetContextAsync() không nhận CancellationToken trực tiếp trong nhiều target framework,
            // ta tự tạo timeout/cancel bằng Task.WhenAny.
            Task<HttpListenerContext> waitTask = listener.GetContextAsync();

            // Nếu bạn muốn timeout rõ ràng, bạn có thể đặt TimeSpan tùy ý
            Task finished = await Task.WhenAny(waitTask, Task.Delay(TimeSpan.FromMinutes(3), ct)).ConfigureAwait(false);

            // Nếu Task.Delay hoàn thành trước => timeout/cancel
            if (finished != waitTask)
                throw new TimeoutException("Timed out waiting for DocuSign OAuth callback.");

            // Lấy context callback
            HttpListenerContext context = await waitTask.ConfigureAwait(false);

            // Lấy query string từ request
            string code = context.Request.QueryString["code"];
            string state = context.Request.QueryString["state"];

            // Trả HTML về cho trình duyệt (người dùng biết đã xong)
            string html = "<html><body><h3>DocuSign OAuth completed.</h3><p>You can close this tab.</p></body></html>";
            byte[] buffer = Encoding.UTF8.GetBytes(html);

            context.Response.ContentType = "text/html; charset=utf-8";
            context.Response.ContentLength64 = buffer.Length;

            // Ghi HTML vào response stream
            await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length, ct).ConfigureAwait(false);
            context.Response.OutputStream.Close();

            // Kiểm tra state chống CSRF
            if (!string.Equals(state, _state, StringComparison.Ordinal))
                throw new InvalidOperationException($"State mismatch. Expected={_state}, got={state}");

            // Kiểm tra code
            if (string.IsNullOrWhiteSpace(code))
                throw new InvalidOperationException("No authorization code received.");

            return code;
        }
        finally
        {
            // Dừng listener để giải phóng port
            if (listener.IsListening)
                listener.Stop();

            listener.Close();
        }
    }

    /// <summary>
    /// Đổi authorization code lấy access token + refresh token
    /// </summary>
    /// <param name="authorizationCode"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    /// <exception cref="HttpRequestException"></exception>
    private async Task<TokenResponse> ExchangeCodeForTokensAsync(string authorizationCode, CancellationToken ct)
    {
        // Tạo request POST /oauth/token
        using (var req = new HttpRequestMessage(HttpMethod.Post, TokenUri))
        {
            // Authorization: Basic base64(client_id:client_secret)
            req.Headers.Authorization = BuildBasicAuthHeader(_clientId, _clientSecret);

            // Body form-urlencoded theo OAuth:
            // grant_type=authorization_code&code=...&redirect_uri=...
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = authorizationCode,
                ["redirect_uri"] = _redirectUri.TrimEnd('/')
            };

            // Gán content form-urlencoded
            req.Content = new FormUrlEncodedContent(form);

            // Gửi request
            using (var resp = await _http.SendAsync(req, ct).ConfigureAwait(false))
            {
                // Đọc JSON body
                string json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);

                // Nếu lỗi HTTP, ném exception
                if (!resp.IsSuccessStatusCode)
                    throw new HttpRequestException($"Token exchange failed. HTTP {(int)resp.StatusCode}. Body: {json}");

                // Parse JSON
                return JsonConvert.DeserializeObject<TokenResponse>(json);
            }
        }
    }

    /// <summary>
    /// Refresh access token dùng refresh token
    /// </summary>
    /// <param name="refreshToken"></param>
    /// <param name="ct"></param>
    /// <returns></returns>
    /// <exception cref="HttpRequestException"></exception>
    private async Task<TokenResponse> RefreshAccessTokenAsync(string refreshToken, CancellationToken ct)
    {
        // Tạo request POST /oauth/token
        using (var req = new HttpRequestMessage(HttpMethod.Post, TokenUri))
        {
            // Authorization: Basic base64(client_id:client_secret)
            req.Headers.Authorization = BuildBasicAuthHeader(_clientId, _clientSecret);

            // Body form-urlencoded:
            // grant_type=refresh_token&refresh_token=...
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken
            };

            // Gán content
            req.Content = new FormUrlEncodedContent(form);

            // Gửi request
            using (var resp = await _http.SendAsync(req, ct).ConfigureAwait(false))
            {
                // Đọc JSON body
                string json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);

                // Check lỗi
                if (!resp.IsSuccessStatusCode)
                    throw new HttpRequestException($"Refresh token failed. HTTP {(int)resp.StatusCode}. Body: {json}");

                // Parse JSON
                return JsonConvert.DeserializeObject<TokenResponse>(json);
            }
        }
    }

    /// <summary>
    /// Lưu thông tin token gọi api ra tệp tin JSON
    /// </summary>
    private void SaveTokenToJsonFile()
    {
        // Tạo object để lưu ra file
        var save = new TokenFileModel
        {
            AccessToken = _accessToken,
            RefreshToken = _refreshToken,
            AccessTokenExpiresAtUtc = _accessTokenExpiresAtUtc
        };

        // Serialize ra JSON “đẹp”
        string json = JsonConvert.SerializeObject(save, Formatting.Indented);

        // Đảm bảo thư mục tồn tại (nếu user đưa path có folder)
        var dir = Path.GetDirectoryName(_tokenJsonPath);
        if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        // Ghi file
        File.WriteAllText(_tokenJsonPath, json, Encoding.UTF8);
    }

    /// <summary>
    /// Load thông tin token gọi api từ tệp tin lưu trữ
    /// </summary>
    /// <returns></returns>
    private TokenFileModel LoadTokenFromJsonFile()
    {
        // Nếu file không tồn tại -> không có token
        if (!File.Exists(_tokenJsonPath))
            return null;

        // Đọc JSON string từ file
        string json = File.ReadAllText(_tokenJsonPath, Encoding.UTF8);

        // Deserialize JSON -> TokenFileModel
        var model = JsonConvert.DeserializeObject<TokenFileModel>(json);

        // Nếu model rỗng hoặc thiếu token thì coi như không hợp lệ
        if (model == null || string.IsNullOrWhiteSpace(model.AccessToken))
            return null;

        return model;
    }

    /// <summary>
    /// Xây dựng header Authorization: Basic base64(client_id:client_secret)
    /// Theo yêu cầu gọi API từ Docusign
    /// </summary>
    /// <param name="clientId"></param>
    /// <param name="clientSecret"></param>
    /// <returns></returns>
    private static AuthenticationHeaderValue BuildBasicAuthHeader(string clientId, string clientSecret)
    {
        // Ghép theo format "client_id:client_secret"
        string raw = $"{clientId}:{clientSecret}";

        // Encode UTF8 -> bytes
        byte[] rawBytes = Encoding.UTF8.GetBytes(raw);

        // Base64 bytes -> string
        string b64 = Convert.ToBase64String(rawBytes);

        // Trả về Authorization header: Basic <b64>
        return new AuthenticationHeaderValue("Basic", b64);
    }

    /// <summary>
    /// Chuyển dictionary key/value thành query string
    /// </summary>
    /// <param name="query"></param>
    /// <returns></returns>
    private static string ToQueryString(Dictionary<string, string> query)
    {
        // StringBuilder để build query string hiệu quả
        var sb = new StringBuilder();

        // Duyệt tất cả key/value
        foreach (var kv in query)
        {
            // Nếu không phải phần tử đầu tiên, thêm "&"
            if (sb.Length > 0) sb.Append("&");

            // Escape key và value để an toàn URL
            sb.Append(Uri.EscapeDataString(kv.Key));
            sb.Append("=");
            sb.Append(Uri.EscapeDataString(kv.Value ?? ""));
        }

        return sb.ToString();
    }

    // Model lưu vào file JSON
    private sealed class TokenFileModel
    {
        // Access token
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        // Refresh token
        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }

        // Thời điểm hết hạn token (UTC) để lần sau load lên biết có cần refresh hay không
        [JsonProperty("access_token_expires_at_utc")]
        public DateTime AccessTokenExpiresAtUtc { get; set; }
    }

    // Response của /oauth/token
    private sealed class TokenResponse
    {
        // access_token
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        // token_type (Bearer)
        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        // refresh_token (chỉ có khi scope có offline_access)
        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }

        // expires_in (seconds)
        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }
    }

    // Response của /oauth/userinfo
    private sealed class UserInfoResponse
    {
        [JsonProperty("sub")]
        public string Sub { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("email")]
        public string Email { get; set; }

        [JsonProperty("accounts")]
        public List<UserInfoAccount> Accounts { get; set; }
    }

    private sealed class UserInfoAccount
    {
        // account_id (GUID)
        [JsonProperty("account_id")]
        public string AccountId { get; set; }

        // is_default
        [JsonProperty("is_default")]
        public bool IsDefault { get; set; }

        // account_name
        [JsonProperty("account_name")]
        public string AccountName { get; set; }

        // base_uri (vd: https://demo.docusign.net)
        [JsonProperty("base_uri")]
        public string BaseUri { get; set; }
    }
}
