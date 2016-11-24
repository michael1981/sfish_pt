#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21223);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-1250");
  script_bugtraq_id(17009);
  script_xref(name:"OSVDB", value:"23877");

  script_name(english:"Winmail Server Webmail Unspecified Vulnerability");
  script_summary(english:"Checks version of Winmail Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote webmail server is affected by an unspecified issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Winmail Server, a commercial mail server
for Windows from AMAX Information Technologies.

According to its version number, the remote installation of Winmail
Server is affected by an unknown issue in its webmail component. It
is unclear whether this is the same issue identified by Secunia in 
November 2005 and covered by Bugtraq ID 15493." );
 script_set_attribute(attribute:"see_also", value:"http://www.magicwinmail.net/changelog.asp" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Winmail Server 4.3(Build 0302) or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 6080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:6080);
if (!get_port_state(port)) exit(0);


# Get the version number from the webmail server's banner.
res = http_get_cache(item:"/", port:port);
if (
  res && 
  "Winmail Server Webmail bases on the UebiMiau." &&
  egrep(pattern:"WebMail \| Powered by Winmail Server ([0-3]\.|4\.[0-2])", string:res)
) security_hole(port);
