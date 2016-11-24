#
# (C) Tenable Network Security, Inc.
#

#
# This script was originally written by Tenable Network Security and
# modified by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

include( 'compat.inc' );

if (description) {
  script_id(14228);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2004-0519", "CVE-2004-0520", "CVE-2004-0521");
  script_bugtraq_id(10246, 10397, 10439);
  script_xref(name:"GLSA", value:"GLSA-200405-16:02");
  script_xref(name:"GLSA", value:"GLSA-200406-08");
  script_xref(name:"OSVDB", value:"6337");
  script_xref(name:"OSVDB", value:"6514");
  script_xref(name:"OSVDB", value:"6841");
  script_xref(name:"OSVDB", value:"8292");
  script_xref(name:"RHSA", value:"RHSA-2004:240-06");

  script_name(english:"SquirrelMail < 1.4.3 Multiple Vulnerabilities");
  script_summary(english:"SquirrelMail XSS and Local escalation");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to injection attacks allowing command execution.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running SquirrelMail, a web-based mail server.

There are several flaws in all versions less than 1.4.3 and development
versions 1.5.0 and 1.5.1 which allow for local root access and remote
Cross-Site-Scripting (XSS) attacks.

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of Squirrelmail
***** installed there.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to SquirrelMail 1.4.3 or greater.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=108334862800260'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securityfocus.com/advisories/6761'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port))
	exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/squirrelmail"));
if (isnull(installs))
	exit(0);
foreach install (installs)
{
	matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  	if (!isnull(matches))
	{
    		ver = matches[1];
    		dir = matches[2];

    		if (ereg(pattern:"^(0\..*|1\.([0-3]\..*|4\.[1-2]|4\.3\-RC1|5\.0|5\.1))$", string:ver))
		{
      			security_hole(port);
			set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      			exit(0);
    		}
  	}
}
