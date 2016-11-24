#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2
#


include("compat.inc");

if (description) {
  script_id(20379);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-4357", "CVE-2005-4358");
  script_bugtraq_id(16088);
  script_xref(name:"OSVDB", value:"21803");
  script_xref(name:"OSVDB", value:"21804");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several flaws." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote version of this software
is vulnerable to JavaScript injection issues using 'url' bbcode tags
and, if HTML tags are enabled, HTML more generally.  This may allow an
attacker to inject hostile JavaScript into the forum system, to steal
cookie credentials or misrepresent site content.  When the form is
submitted the malicious JavaScript will be incorporated into
dynamically generated content. 

In addition, an attacker may be able to learn the full path of the
install by calling 'admin/admin_disallow.php' provided PHP's
'register_globals' and 'display_errors' are both enabled." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-December/040204.html " );
 script_set_attribute(attribute:"see_also", value:"http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=352966" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpBB version 2.0.19 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  script_name(english:"phpBB < 2.0.19 Multiple XSS");
  script_summary(english:"Checks for multiple cross-site scripting flaws in phpBB <= 2.0.18");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006-2009 David Maciejak");

  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");


if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);


matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
	version = matches[1];
	if ( ereg(pattern:"^([01]\..*|2\.0\.([0-9]|1[0-8])[^0-9])", string:version)) {
	   security_warning(port);
	   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	   exit(0);
	}
}
