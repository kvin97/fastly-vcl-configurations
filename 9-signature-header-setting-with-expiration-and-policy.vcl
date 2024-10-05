# Add this within vcl_deliver subroutine (priority 100)
# This is required to set req headers in resp object
# Remove or replace 7-signature-header-setting.vcl snippet when you are testing 

set resp.http.X-Sig-Url = req.http.X-Sig-Url;
set resp.http.X-Sig-Signature = req.http.X-Sig-Signature;
set resp.http.X-Sig-Verification-Value = req.http.X-Sig-Verification-Value;
set resp.http.X-Sig-Verification = req.http.X-Sig-Verification;
set resp.http.X-Sig-Expire = req.http.X-Sig-Expire;
set resp.http.X-Sig-Policy = req.http.X-Sig-Policy;
set resp.http.X-Sig-Allowed-Methods = req.http.X-Sig-Allowed-Methods;
set resp.http.X-Sig-Policy-Decoded = req.http.X-Sig-Policy-Decoded;
set resp.http.X-Sig-Policy-Not-Decoded = req.http.X-Sig-Policy-Not-Decoded;