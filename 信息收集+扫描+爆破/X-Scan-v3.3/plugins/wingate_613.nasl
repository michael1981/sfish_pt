#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21674);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-2926");
  script_bugtraq_id(18312);
  script_xref(name:"OSVDB", value:"26214");

  script_name(english:"WinGate POST Request Buffer Overflow");
  script_summary(english:"Checks version number in WinGate's banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote HTTP proxy server is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running WinGate Proxy Server, a Windows
application for managing and securing Internet access. 

According to its banner, the version of WinGate installed on the
remote host is affected by a buffer overflow vulnerability in its HTTP
proxy service.  An attacker with access to use the proxy may be able
to exploit this issue to execute arbitrary code on the remote host. 

Note that by default the service operates with LOCAL SYSTEM
privileges, which means that a successful attack may result in a
complete compromise of the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-June/046646.html" );
 script_set_attribute(attribute:"see_also", value:"http://forums.qbik.com/viewtopic.php?t=4215" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WinGate 6.1.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# There's a problem if the banner is for WinGate < 6.1.3.
banner = get_http_banner(port:port);
if (
  banner &&
  egrep(pattern:"^Server: +WinGate ([0-5]\.|6\.(0\.|1\.[0-2][^0-9]))", string:banner)
) security_hole(port);
