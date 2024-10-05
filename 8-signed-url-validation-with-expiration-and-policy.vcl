# Add this within vcl_recv subroutine (priority 100)
# This is required for signed URL validation with expiration and policy
# Remove or replace 6-signed-url-validation.vcl snippet when you are testing 

declare local var.stringToSign STRING;
declare local var.signature STRING;
declare local var.expires INTEGER;
declare local var.isVerified STRING;
declare local var.policy STRING;
declare local var.policy_decoded STRING;
declare local var.allowedMethods STRING;

log "Fetch Starting for sig verification !";

if (req.url ~ "signature=") {
    set var.signature = querystring.get(req.url, "signature");

    set req.url = regsub(req.url, "(?i)([?&]signature=[^&]*)", "");
    set req.url = regsub(req.url, "[?&]$", "");  # Remove any trailing '?' or '&'
} else {
    error 618 "signature not included";
}

set var.stringToSign = req.url;

set var.isVerified = digest.rsa_verify(sha256, {"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmwJSEdqGHLa8UHrBQYFP
8vmpT6VZxTYL9odMPVkb7quNBYdQedLhdLffIrO/yh27m9zDYGTIuRGArp/anxbO
sjqxKY90V5c3rJNEH32/GOO8/BPUzPEg/f/st4WkQ1pykOpP9ltRHe5u4l5gy4zC
nsImTUCHeyFjYULkAZyVPxgIGhAIT4biBDH4zfDbFIpeuHoyy2H5HDEki95OWn5g
zwJ7MJXEoWT0PWscb3DYXmGufoqmtncbck04cqQBew2lb5om30+zqzWINdhCC127
ChiSCcsuwlGBCgHKoVXVhJkc+289dmU4mak/dIIG45BN8FlGnUoiA4P1j9Gh5c0Q
+wIDAQAB
-----END PUBLIC KEY-----"}, var.stringToSign, var.signature, standard);

set req.http.X-Sig-Url = var.stringToSign;
set req.http.X-Sig-Signature = var.signature;
set req.http.X-Sig-Verification-Value = var.isVerified;

if(var.isVerified == "1") {
    set req.http.X-Sig-Verification = "Verified";
} else {
    set req.http.X-Sig-Verification = "Not Verified";
    error 619 "signature invalid";
}

if (req.url ~ "expires=") {
    set var.expires = std.strtol(querystring.get(req.url, "expires"), 10);

    set req.url = regsub(req.url, "(?i)([?&]expires=[^&]*)", "");
    set req.url = regsub(req.url, "[?&]$", "");  # Remove any trailing '?' or '&'
} else {
    error 620 "expires query parameter not included";
}

if (var.expires > 0 && !time.is_after(now, std.integer2time(var.expires))) {
    set req.http.X-Sig-Expire = "Not Expired";
} else {
    set req.http.X-Sig-Expire = "Expired";
    error 621 "signature is expired";
}

if (req.url ~ "policy=") {
    set var.policy = querystring.get(req.url, "policy");

    set req.url = regsub(req.url, "(?i)([?&]policy=[^&]*)", ""); # remove policy query param
    set req.url = regsub(req.url, "[?&]$", "");  # Remove any trailing '?' or '&'

    set var.policy_decoded = digest.base64url_decode(var.policy); # decode base64 string
} else {
    set req.http.X-Sig-Policy = "Not Allowed";
    set req.http.X-Sig-Allowed-Methods = "";
    error 622 "policy query parameter not included";
}

set req.http.X-Sig-Policy-Not-Decoded = var.policy;

set var.policy_decoded = digest.base64url_decode(var.policy);

set req.http.X-Sig-Policy-Decoded = var.policy_decoded;

set var.allowedMethods = if(var.policy_decoded ~ {"\{(?:.+,)?\s*"allowedMethods" *: *"([^"]*)""}, re.group.1, ""); # extract allowed methods field

set req.http.X-Sig-Allowed-Methods = var.allowedMethods;

# allowed requested methods categorized under 3 categories as follows
if (var.allowedMethods == "GET|HEAD|OPTIONS|PUT|POST|PATCH|DELETE" && req.method ~ "GET|HEAD|OPTIONS|PUT|POST|PATCH|DELETE") {
    set req.http.X-Sig-Policy = "Allowed";
} else if (var.allowedMethods == "GET|HEAD|OPTIONS" && req.method ~ "GET|HEAD|OPTIONS") {
    set req.http.X-Sig-Policy = "Allowed";
}
else if (var.allowedMethods == "GET|HEAD" && req.method ~ "GET|HEAD") { 
    set req.http.X-Sig-Policy = "Allowed";
}
else {
    set req.http.X-Sig-Policy = "Not Allowed";
    error 623 "policy does not authorize the user to access the requested method on the given resource";
}