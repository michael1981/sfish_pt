#
# (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(24756);
  script_version("$Revision: 1.4 $");
  script_xref(name:"OSVDB", value:"53348");

  script_name(english:"Symantec Mail Security for SMTP Admin Center Default Credentials");
  script_summary(english:"Tries to authenticate to SMS for SMTP");
 
 script_set_attribute(attribute:"synopsis", value:
"An application hosted on the remote web server is protected with
default credentials." );
 script_set_attribute(attribute:"description", value:
"Symantec Mail Security for SMTP, which provides anti-spam and anti-
virus protection for the IIS SMTP Service, is installed on the remote
Windows host. 

The installation of SMS for SMTP on the remote host uses a default
username / password combination to control access to its
administrative control center.  Knowing these, an attacker can gain
control of the affected application." );
 script_set_attribute(attribute:"solution", value:
"Use the control center to add another administrator or alter the
password for the 'admin' account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 41443);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:41443);
if (!get_port_state(port)) exit(0);


# Make sure the affected script exists.
url = "/brightmail/login.do";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

# If it does...
if (
  "Symantec Mail Security" >< res && 
  '<input type="text" name="username"' >< res
)
{
  # Try to authenticate.
  user = "admin";
  pass = "symantec";
  postdata = string(
    "userLocale=&",
    "username=", user, "&",
    "password=", pass, "&",
    "loginBtn=Login"
  );
  req = string(
    "POST ", url, " HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like we were successful.
  if (
    "Location:" >< res &&
    egrep(pattern:"^Location: .+/brightmail/setup/SiteSetupEmbedded\$exec.flo", string:res)
  ) security_hole(port);
}
