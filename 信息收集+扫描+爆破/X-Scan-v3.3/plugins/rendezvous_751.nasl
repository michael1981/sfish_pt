#
# (C) Tenable Network Security
#

include("compat.inc");

if (description)
{
  script_id(21677);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-2830");
  script_bugtraq_id(18301);
  script_xref(name:"OSVDB", value:"26155");

  script_name(english:"Rendezvous < 7.5.1 HTTP Admin Interface Remote Overflow");
  script_summary(english:"Checks version number in Rendezvous' HTTP banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Rendezvous, a commercial
messaging software product used for building distributed applications

According to its banner, several of the components in the version of
Rendezvous installed on the remote host contain a buffer overflow
vulnerability in the HTTP administrative interface that may allow
arbitrary code execution subject to the privileges of the user that
invoked the daemon, or 'nobody' in the case the remote system is
'unix' and the invoking user was 'root'." );
 script_set_attribute(attribute:"see_also", value:"http://www.tibco.com/resources/mk/rendezvous_security_advisory.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/999884" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Rendezvous 7.5.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7580, 7585);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:7580);


# There's a problem if the banner is for Rendezvous < 7.5.1.
banner = get_http_banner(port:port);
if (
  banner &&
  egrep(pattern:"^Server: .+Rendezvous HTTP Server ([0-6]\.|7\.([0-4]\.|5\.0))", string:banner)
) security_hole(port);
