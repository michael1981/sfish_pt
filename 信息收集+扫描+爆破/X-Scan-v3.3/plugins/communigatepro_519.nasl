#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25215);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-2718");
  script_bugtraq_id(23950);
  script_xref(name:"OSVDB", value:"36017");

  script_name(english:"CommuniGate Pro WebMail w/ MSIE STYLE Tag XSS");
  script_summary(english:"Checks for CommuniGate Pro < 5.1.9");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of CommuniGate Pro running on the
remote host fails to completely sanitize email messages.  A remote
attacker may be able to leverage this issue to inject arbitrary HTML
and script code into a user's browser to be evaluated within the
security context of the affected web site." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-05/0186.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.communigate.com/CommuniGatePro/History51.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CommuniGate Pro version 5.1.9 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8100);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8100);

# Check the version in the banner.
banner = get_http_banner(port:port);
if (
  banner &&
  "Server: CommuniGatePro" >< banner &&
  egrep(pattern:"^Server: CommuniGatePro/([0-4]\.|5\.(0[^0-9]|1([^.]|\.[0-8]($|[^0-9]))))", string:banner)
) {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
