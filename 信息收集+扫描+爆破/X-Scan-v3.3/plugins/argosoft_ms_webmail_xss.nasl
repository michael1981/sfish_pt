#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(20985);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-0978");
  script_bugtraq_id(16834);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"23512");
  }

  script_name(english:"ArGoSoft Mail Server Pro Webmail viewheaders Multiple Field XSS");
  script_summary(english:"Checks version of ArGoSoft Mail Server Pro banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ArGoSoft Mail Server Pro, a messaging
system for Windows. 

According to its banner, the webmail server bundled with the version
of ArGoSoft Mail Server Pro installed on the remote host fails to
properly filter message headers before displaying them as part of a
message to users.  A remote attacker may be able to exploit this issue
to inject arbitrary HTML and script code into a user's browser, to be
executed within the security context of the affected web site." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-6/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.argosoft.com/rootpages/MailServer/ChangeList.aspx" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft Mail Server Pro version 1.8.8.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Check the banner.
banner = get_http_banner(port:port);
if (
  banner && 
  egrep(pattern:"^Server: ArGoSoft Mail Server Pro.+ \((0\.|1\.([0-7]\.|8\.([0-7]|8\.[0-5])))", string:banner)
) {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
