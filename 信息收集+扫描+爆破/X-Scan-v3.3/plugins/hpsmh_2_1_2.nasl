#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25352);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-3062");
  script_bugtraq_id(24256);
  script_xref(name:"OSVDB", value:"36829");

  script_name(english:"HP System Management Homepage < 2.1.2 Unspecified XSS");
  script_summary(english:"Checks version of HP SMH");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running HP System Management Homepage
(SMH), a web-based management interface for ProLiant and Integrity
servers. 

The version of HP SMH installed on the remote host fails to sanitize
user input to unspecified parameters and scripts before using it to
generate dynamic HTML.  A remote attacker may be able to exploit these
issues to cause arbitrary HTML and script code to be executed by a
user's browser in the context of the affected web site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/12545" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to HP System Management Homepage v2.1.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:2301);

banner = get_http_banner(port:port);
if (!banner) exit(0);

if (egrep(pattern:"^Server: .*System Management Homepage/(1\.|2\.(0\.|1\.[01]\.))", string:banner))
{
  security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

