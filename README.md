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
Nếu là lần đầu thì nó sẽ bắt đăng nhập tài khoản `DocuSign`. và sau đó nó sẽ chuyển hướng sang 1 trang mới có code như sau:  

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

![image](Github_Img//request_access_token.png)  

```
curl --header "Authorization: Basic BASE64_COMBINATION_OF_INTEGRATION_AND_SECRET_KEYS"
--data "grant_type=authorization_code&code=YOUR_AUTHORIZATION_CODE"
--request POST https://account-d.docusign.com/oauth/token
```
Có 1 lưu ý là `Authorization` của đoạn mã này có định dạng `Basic BASE64_COMBINATION_OF_INTEGRATION_AND_SECRET_KEYS` nghĩa là ta cần ghép nối mã `Integration và Secret Key` thành định dạng `Base 64`.  
