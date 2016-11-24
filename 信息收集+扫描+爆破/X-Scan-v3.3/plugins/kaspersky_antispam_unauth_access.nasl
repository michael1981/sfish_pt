#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25626);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-3502");
  script_bugtraq_id(24692);
  script_xref(name:"OSVDB", value:"37217");

  script_name(english:"Kaspersky Anti-Spam Control Center Web Config aslic_status.cgi Directory Listing");
  script_summary(english:"Tries to get a directory listing");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to an information disclosure
attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Kaspersky Anti-Spam's Control
Center. 

The version of the Kaspersky Anti-Spam Control Center installed on the
remote host fails to require authentication for access to directories
under the service's document root.  An unauthenticated remote attacker
may be able to leverage this issue to obtain sensitive information
from the remote host. 

Note that the Control Center listens only on the loopback interface by
default." );
 script_set_attribute(attribute:"see_also", value:"http://www.kaspersky.com/technews?id=203038700" );
 script_set_attribute(attribute:"solution", value:
"Apply Critical Fix 1 for Kaspersky Anti-Spam 3.0 MP1." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3080);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:3080);

# Make sure it's KAS.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Server: thttpd/" >!< banner) exit(0);
}

r = http_send_recv3(method:"GET", item:"/aslic_status.cgi", port:port);
if (isnull(r)) exit(0);
res = r[2];

# If so...
if ("Authorization required for the URL '/aslic_status.cgi'" >< res)
{
  # Try to exploit the vulnerability to get a directory listing.
  r = http_send_recv3(method:"GET", item:"/stat/", port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we get a directory listing.
  if ("<TITLE>Index of /stat/</TITLE>" >< res)
    security_hole(port);
}
