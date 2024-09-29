# Add this within vcl_miss subroutine (priority 100)
# This is required to access private S3 bucket with AWS Sig V4 authentication

declare local var.awsAccessKey STRING;
declare local var.awsSecretKey STRING;
declare local var.awsS3Bucket STRING;
declare local var.awsRegion STRING;
declare local var.canonicalHeaders STRING;
declare local var.signedHeaders STRING;
declare local var.canonicalRequest STRING;
declare local var.canonicalQuery STRING;
declare local var.stringToSign STRING;
declare local var.dateStamp STRING;
declare local var.signature STRING;
declare local var.scope STRING;

set var.awsAccessKey = "***";   
set var.awsSecretKey = "***";
set var.awsRegion = "us-east-1"; 

if (req.method == "GET" && !req.backend.is_shield) {

  set bereq.http.x-amz-content-sha256 = digest.hash_sha256("");
  set bereq.http.x-amz-date = strftime({"%Y%m%dT%H%M%SZ"}, now);

  if (bereq.url ~ "^/payment/") {
    set var.awsS3Bucket = "my-fashion-store-payment"; # /payment path
  } else if (bereq.url ~ "^/invoice/") {
    set var.awsS3Bucket = "my-fashion-store-invoice"; # /invoice path
  } else {
    set var.awsS3Bucket = "my-fashion-store-invoice"; # default path
  }
  
  set bereq.http.previoushost = bereq.http.host; # backend request previous host header for inspection
  
  set bereq.http.host = var.awsS3Bucket ".s3." var.awsRegion ".amazonaws.com";
  
  set bereq.http.updatedhost = bereq.http.host; # backend request updated host header for inspection
  
  set bereq.url = querystring.remove(bereq.url);
  set bereq.url = regsuball(urlencode(urldecode(bereq.url.path)), {"%2F"}, "/");
  set var.dateStamp = strftime({"%Y%m%d"}, now);
  set var.canonicalHeaders = ""
    "host:" bereq.http.host LF
    "x-amz-content-sha256:" bereq.http.x-amz-content-sha256 LF
    "x-amz-date:" bereq.http.x-amz-date LF
  ;
  set var.canonicalQuery = "";
  set var.signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  set var.canonicalRequest = ""
    "GET" LF
    bereq.url.path LF
    var.canonicalQuery LF
    var.canonicalHeaders LF
    var.signedHeaders LF
    digest.hash_sha256("")
  ;

  set var.scope = var.dateStamp "/" var.awsRegion "/s3/aws4_request";

  set var.stringToSign = ""
    "AWS4-HMAC-SHA256" LF
    bereq.http.x-amz-date LF
    var.scope LF
    regsub(digest.hash_sha256(var.canonicalRequest),"^0x", "")
  ;

  set var.signature = digest.awsv4_hmac(
    var.awsSecretKey,
    var.dateStamp,
    var.awsRegion,
    "s3",
    var.stringToSign
  );

  set bereq.http.Authorization = "AWS4-HMAC-SHA256 "
    "Credential=" var.awsAccessKey "/" var.scope ", "
    "SignedHeaders=" var.signedHeaders ", "
    "Signature=" + regsub(var.signature,"^0x", "")
  ;
  unset bereq.http.Accept;
  unset bereq.http.Accept-Language;
  unset bereq.http.User-Agent;
  unset bereq.http.Fastly-Client-IP;
}