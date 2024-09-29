# Add this within vcl_fetch subroutine (priority 100)
# This is required to set bereq headers in beresp to view them at client response (optional)

set beresp.http.previoushost = bereq.http.previoushost;
set beresp.http.updatedhost = bereq.http.updatedhost;
set beresp.http.actualhost = bereq.http.host;