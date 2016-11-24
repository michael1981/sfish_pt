#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(30211);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-0457");
  script_bugtraq_id(27487);
  script_xref(name:"OSVDB", value:"41149");

  script_name(english:"Symantec Backup Exec System Recovery Manager FileUpload Class Unauthorized File Upload");
  script_summary(english:"Checks for reportsfile parameter directory traversal vulnerability in Symantec BESRM 7");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Tomcat servlet that fails to validate
user input." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Symantec Backup Exec System
Recovery Manager, a backup manager solution. 

The version of Recovery Manager on the remote host includes the Tomcat
Servlet 'FileUpload' that fails to validate the user input.  An
unauthenticated attacker may be able to exploit this issue to upload a
jsp script to execute code on the remote host with SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.02.04.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 7.0.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if ("Apache-Coyote" >!< banner) exit(0);


req = http_get(port:port, item:"/axis/FileUpload");
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if ("HTTP method GET is not supported by this URL" >!< res) exit(0);

# path does not exist -> exception
# fixed version exit due to ".."
fname = string("nessus-", unixtime() ,".jsp");
path  = string("nessus-", unixtime());


boundary = "nessus";

req = string(
      "POST /axis/FileUpload HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      #"User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );

boundary = string("--", boundary);

postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="path"\r\n',
      "\r\n",
      path, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="log_file"; filename="', fname, '"', "\r\n",
      "Content-Type: application/octet-stream\r\n",
      "\r\n",
      "NESSUS\r\n",

      boundary, "--", "\r\n"
    );

req = string(
      req,
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );

res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL) exit(0);

msg = string(path, "\\", fname, " (The system cannot find the path specified");
if (msg >< res)
  security_hole(port);
