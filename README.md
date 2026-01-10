# I. Tạo môi trường ảo

Chạy các lệnh sau vào `Terminal` của dự án để tạo môi trường ảo và kích hoạt nó.  
```python
py -3.12 -m venv .venvDocuSign --prompt="DocuSign"
```
Có thể thay thế phiên bản python bằng phiên bản của bạn hiện đang sử dụng. Tuy nhiên dự án này hiện tại đang được sử dụng tại phiên bản `python 3.12.4`.  

Kích hoạt môi trường ảo.  
```python
.venvDocuSign\Scripts\activate
```
![image](Github_Img/activate_venv.png)  

# II. Tạo tài khoản dev của DocuSign

Để sử dụng các API của `DocuSign` thì cần có tài khoản dev của trang này. Ta tạo 1 tài khoản Dev, sau đó đăng nhập.  

![image](Github_Img/account_docusign.png)  

Sau đó tạo 1 `App and Integration Keys`. Ta cần lưu ý các thông tin sau trong app.  

Đầu tiên ta cần ghi nhớ `Integration Key` của ứng dụng.  

![image](Github_Img/integration_key.png)  

Mục `Authentication` ta cần lưu giữ `Secret Key`, nó chỉ xuất hiện 1 lần và không hiển thị lại, vì vậy ta cần lưu nó khi tạo `Secret Key`.  

![image](Github_Img/secret_key_app.png)  

Tại mục `Additional Settings` -- > `Redirect URL` ta cần ghi nhớ một trong các url này để sử dụng cho mục đích lấy `Authentication Code`.  

![image](Github_Img/redirect_url.png)  


# III. Truy vấn Access token

Để gọi bất kỳ api nào liên quan đến chữ ký điện tử, ta đều cần có `Access Token` thì mới có thể xác thực được yêu cầu. Tài liệu hướng dẫn lấy `Access Token` có thể tham khảo [tại đây](https://developers.docusign.com/platform/auth/confidential-authcode-get-token/).  

Các thông tin ta cần có để lấy được `Access Token` như sau:  
- Integrarion Key  
- Redirect URL  
- Secrect Key  

Các thông tin có thể được tìm thấy tại mục `My App & Key`.  

![image](Github_Img/My_app_and_key.png)  

Để lấy đưuọc `Access Token` khá là rắc rối, đầu tiên ta phải có `Authorization code` bằng cách gọi một url.  
```link
https://account-d.docusign.com/oauth/auth?
   response_type=code
   &scope=YOUR_REQUESTED_SCOPES
   &client_id=YOUR_INTEGRATION_KEY
   &state=YOUR_CUSTOM_STATE
   &redirect_uri=YOUR_REDIRECT_URI
   &login_hint=YOUR_LOGIN_EMAIL
```

![image](Github_Img/request_authorization_code.png)  

Ta có thể sử dụng url mẫu như sau:  
```
https://account-d.docusign.com/oauth/auth?response_type=code&scope=signature&client_id=7c2b8d7e-xxxx-xxxx-xxxx-cda8a50dd73f&state=a39fh23hnf23&redirect_uri=http://example.com/callback&login_hint=example@example.com 
```
Ta thay thế các đoạn `Client_id` (integration code), `redirect_url` (redirect url) và `login_hint` (email login) tương ứng.  

Sau khi truy cập url này:  
Nếu là lần đầu thì nó sẽ bắt đăng nhập tài khoản `DocuSign`.  

![image](Github_Img/login_request_authorization_code.png)  

Và sau đó nó sẽ chuyển hướng sang 1 trang mới có code như sau:  

![image](Github_Img/get_authorization_code.png)

Ta nhìn vào url trên thanh web có dạng:  
```
https://localhost:3000/ds/callback?code=eyJ0eXAiOiJNVCIsImFsZyI6IlJTMjU2Iiwia2lkIjoiNjgxODVmZjEtNGU1MS00Y2U5LWFmMWMtNjg5ODEyMjAzMzE3In0.AQoAAAABAAYABwCAvWoS9EHeSAgAgEnxWfRB3kgCADV9cjmk1ZVGgtf-MOpDcrwVAAEAAAAYAAEAAAAFAAAADQAkAAAANjdkZTQ5NGYtOTNkYy00NWZiLWFlMjctMDhlMDM4MjQ3ZDJjIgAxxxxxxxxxxxxx
```
Trong đó `https://localhost:3000/ds/callback` là `Redirct url` ta truyền vào, ta cần đoạn mã phía sau chữ `code`:  
```
eyJ0eXAiOiJNVCIsImFsZyI6IlJTMjU2Iiwia2lkIjoiNjgxODVmZjEtNGU1MS00Y2U5LWFmMWMtNjg5ODEyMjAzMzE3In0.AQoAAAABAAYABwCAvWoS9EHeSAgAgEnxWfRB3kgCADV9cjmk1ZVGgtf-MOpDcrwVAAEAAAAYAAEAAAAFAAAADQAkAAAANjdkZTQ5NGYtOTNkYy00NWZiLWFlMjctMDhlMDM4MjQ3ZDJjIgAxxxxxxxxxxxxx
```

Khi đã có `Authorization code` thì ta đã có thể lấy `Access token` như sau:  

![image](Github_Img/request_access_token.png)  

```
curl --header "Authorization: Basic BASE64_COMBINATION_OF_INTEGRATION_AND_SECRET_KEYS"
--data "grant_type=authorization_code&code=YOUR_AUTHORIZATION_CODE"
--request POST https://account-d.docusign.com/oauth/token
```
Có 1 lưu ý là `Authorization` của đoạn mã này có định dạng `Basic BASE64_COMBINATION_OF_INTEGRATION_AND_SECRET_KEYS` nghĩa là ta cần ghép nối mã `Integration và Secret Key` thành định dạng `Base 64`.  

Tham khảo đoạn code [Tại đây](src/access_token/get_access_token.py)

# IV. Tài liệu cần ký

Tài liệu cần ký gửi qua bằng API nên sử dụng phương pháp `anchor text` thay vì `anchor position`. Có nghĩa là ta sẽ đặt 1 dòng văn bản, đánh dấu cho việc là chữ ký sẽ nằm ở đây, thay vì ta đặt bằng tạo độ x, y tuyệt đối. Khi thay đổi kích thước hay khác thì tọa độ sẽ không còn chính xác như văn bản nữa.  
Ví dụ tôi có ô ký như sau và cần người dùng ký vào đó, thời gian ký ngay bên dưới:  

![image](Github_Img/anchor_signhere.png)  

Ta có thể thấy 2 doàng chữ `/signhere1/` và `/date/`. Đây sẽ là 2 vị trí mà ta sẽ đặt chữ ký và thời gian ký vào đây. Lưu ý chữ ký sẽ bắt đầu tại tọa độ của 2 văn bản này, nó sẽ bắt đầu tại `/`, vì vậy ta nên để nó nằm phía dưới ô kí, góc bên trái để khi chèn chữ ký vào nó sẽ bao phủ hết ô ký, không bị lệch ra ngoài hay không cân đối.  
Và để trông chuyên nghiệp hơn, ta sẽ ẩn đi 2 văn bản đánh dấu này bằng cách chọn cho nó màu trắng.  

![image](Github_Img/anchor_signhere_white_color.png)  

Như vậy bây giờ sẽ không ai nhận ra được ô ký đã được đánh dấu, nhưng khi gửi lên DocuSign thì nó vẫn nhận ra đâu là nơi cần điền chữ ký vào. Mặc định thời gian ký sẽ được chèn vào và người ký không thể chỉnh sửa hay làm gì khác.  

# V. Goi API bằng ngôn ngữ C#

Tương tự đối với C# thì ta cần tải thư viện `DocuSign.eSign` từ Nuget để mã có thể chạy được. Mình đã đóng gói đoạn code xử lý thành 1 class [tại đây](C_sharp/DocuSignService.cs). Mình đặt tên cho nó là `DocuSignService`.  

Các vị trí cần gửi báo cáo tới người phê duyệt thì ta khai báo như sau:  
```C#
// DocuSignService
private DocuSignService _docusign;

private async Task EnsureDocuSignInitializedAsync()
{
    if (_docusign != null) return;

    _docusign = new DocuSignService(
        clientId: "67de494f-93dc-45fb-ae27-08e038247d2c",                                            // Client id của app trong DocuSign
        clientSecret: "17e02092-9d32-4da0-8636-a7bc8632b550",                                        // Client Secret của app trong DocuSign
        redirectUri: "http://localhost:3000/ds/callback",                                            // nhớ đăng ký trong Apps and Keys, và sử dụng http thay vì htpps
        scopes: "signature offline_access",
        tokenJsonPath: Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "docusign_tokens.json"),  // Nơi lưu trữ access token sử dụng cho lần sau thay vì cứ request mãi
        loginHintEmail: "tvc_adm_it@terumo.co.jp"                                                    // Địa chỉ email dùng để gợi ý đăng nhập khi lấy access token
    );

    // Init: nếu chưa có token.json sẽ tự mở browser xin consent
    await _docusign.InitializeAsync();
}
```
Đầu tiên ta khai báo biến cho class `DocuSignService` và tạo 1 hàm khởi tạo để lấy token từ DocuSign.  
Sau đó bất kỳ thao tác nào với 1 tệp báo cáo thì ta đều cần chuyển nó về dạng `bytes` thì mới có thể gửi nó tới DocuSign. Ví dụ tôi đang thao tác với `XtraReport`, 1 dạng báo cáo trong C#, bạn cũng có thể thay thế nó bằng đường dẫn tới 1 tệp PDF bất kỳ, đọc tệp PDF đó và chuyển đổi nó thành dạng `bytes` và đặt tên cho PDF đã chuyển đổi có tên `pdfBytes` để tương đồng với hàm bên dưới là được.  
```C#
private async Task SendForESignatureAsync(XtraReport report, IWin32Window owner)
{
    // Khởi tạo docuSign service
    await EnsureDocuSignInitializedAsync();

    var signerName = "Nguyễn Đức Quân";
    var signerEmail = "nguyenducquan2001@gmail.com";

    // Export PDF sang dạng byte để gửi DocuSign
    byte[] pdfBytes;
    using (var ms = new MemoryStream())
    {
        report.ExportToPdf(ms);
        pdfBytes = ms.ToArray();
    }

    // Gửi DocuSign
    try
    {
        // Anchor phải khớp text đã chèn trong report (Khu vực yêu cầu ký)
        string anchor = "/signhere1/";

        var envelopeId = await _docusign.SendPdfForSignatureViaEmailAsync(
            pdfBytes: pdfBytes,
            documentName: "Report.pdf",
            signerName: signerName,
            signerEmail: signerEmail,
            anchorString: anchor
        );

        MessageBox.Show(owner,
            $"ĐÃ gửi báo cáo tới người ký.\nMã EnvelopeId của báo cáo: {envelopeId}",
            "DocuSign",
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);

        // Lưu envelopeId vào CSDL nếu cần hoặc xử lý tiếp
    }
    catch (Exception ex)
    {
        MessageBox.Show(owner, ex.ToString(), "Gửi báo cáo tới DocuSign thất bại",
            MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
```
Với mỗi `XtraReport` được gọi tới hàm trên thì tôi sẽ gửi nó tới người nhận và địa chỉ email đã được thiết lập ở bên trên. 