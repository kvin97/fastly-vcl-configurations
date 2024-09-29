# Add this within vcl_fetch subroutine (priority 100)
# This is required to keep minimal TTL for 404 errors

if ( beresp.status == 404 ) {
    # 404 Page Not Found
    set beresp.ttl = 1s;
    set beresp.grace = 0s;
    
    return(deliver);
}