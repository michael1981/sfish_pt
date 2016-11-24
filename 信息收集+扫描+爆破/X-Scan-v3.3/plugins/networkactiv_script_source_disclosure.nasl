#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(21154);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-0815");
  script_bugtraq_id(16895);
  script_xref(name:"OSVDB", value:"23543");

  script_name(english:"NetworkActiv Web Server Crafted Filename Request Script Source Disclosure");
  script_summary(english:"Checks version of NetworkActiv Web Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server suffers from an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running NetworkActiv Web Server, a freeware web
server for Windows. 

According to its banner, the installed version of NetworkActiv Web
Server does not properly validate the extension of filenames before
deciding how to serve them.  By including a forward-slash character A
remote attacker may be able to leverage this issue to disclose the
source of scripts hosted by the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-10/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.networkactiv.com/WebServer.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to NetworkActiv Web Server version 3.5.16 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


banner = get_http_banner(port:port);
if (
  banner && 
  egrep(pattern:"^Server: NetworkActiv-Web-Server/([0-2]\.|3\.([0-4]($|\.)|5($|\.[0-9]([^0-9].*)?$|\.1[0-5])))", string:banner)
) security_warning(port);
