#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(19598);
  script_version("$Revision: 1.7 $");

  script_name(english:"Brightmail Control Center Default Password (symantec) for 'admin' Account");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server uses known authentication credentials." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Symantec's Brightmail Control Center, a
web-based administration tool for Brightmail AntiSpam. 

The installation of Brightmail Control Center on the remote host still
has an account 'admin' with the default password 'symantec'.  An
attacker can exploit this issue to gain access of the Control Center
and any scanners it controls." );
 script_set_attribute(attribute:"solution", value:
"Log in to the Brightmail Control Center and change the password for
the 'admin' user." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for default account / password in Brightmail Control Center");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 41080, 41443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:41080);

# Check whether the login script exists.
r = http_send_recv3(method:"GET", item:"/brightmail/viewLogin.do", port:port);
if (isnull(r)) exit(0);
res = r[2];

# If it does...
if ('<form name="logonForm" action="login.do"' >< res) {
  # Try to log in.
  user = "admin";
  pass = "symantec";
  postdata = string(
    "path=&",
    "compositeId=&",
    "username=", user, "&",
    "password=", pass
  );
  r = http_send_recv3(method: "POST", item: "/brightmail/login.do", version: 11, port: port,
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
    data: postdata);
  if (isnull(r)) exit(0);

  # There's a problem if we get redirected to a start page.
  if (egrep(string:r[1], pattern:"^Location: .+/findStartPage.do")) {
    security_hole(port);
    exit(0);
  }
}
