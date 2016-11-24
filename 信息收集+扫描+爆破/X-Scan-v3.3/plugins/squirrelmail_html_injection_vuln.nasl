#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from 
#
#  George A. Theall <theall@tifaware.com>
#  and
#  Tenable Network Security
#
# This script is released under the GNU GPLv2
#
#  Credit: SquirrelMail Team
# 
# modification by George A. Theall
# -change summary
# -remove references to global settings
# -clearer description
# -changed HTTP attack vector -> email

# Changes by Tenable:
# - Revised plugin title (5/30/09)
# - Updated to use compat.inc/Added CVSS score (11/17/2009)


include("compat.inc");

if (description) {
  script_id(14217);
  script_version ("$Revision: 1.15 $");

  script_cve_id("CVE-2004-0639");
  script_bugtraq_id(10450);
  script_xref(name:"OSVDB", value:"8291");
  script_xref(name:"OSVDB", value:"8292");

  script_name(english:"SquirrelMail < 1.2.11 Multiple Script XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
multiple cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of SquirrelMail whose
version number is between 1.2.0 and 1.2.10 inclusive.  Such versions do
not properly sanitize From headers, leaving users vulnerable to XSS
attacks.  Further, since SquirrelMail displays From headers when listing
a folder, attacks does not require a user to actually open a message,
only view the folder listing.

For example, a remote attacker could effectively launch a DoS against
a user by sending a message with a From header such as :

From:<!--<>(-->John Doe<script>document.cookie='PHPSESSID=xxx; path=/';</script><>

which rewrites the session ID cookie and effectively logs the user
out.

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of Squirrelmail
***** installed there." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SquirrelMail 1.2.11 or later or wrap the call to
sqimap_find_displayable_name in printMessageInfo in
functions/mailbox_display.php with a call to htmlentities." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
  summary["english"] = "Check Squirrelmail for HTML injection vulnerability";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");

  script_family(english:"CGI abuses : XSS");

  script_dependencie("squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

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

    		if (ereg(pattern:"^1\.2\.([0-9]|10)$", string:ver)) 
		{
      			security_warning(port);
			set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      			exit(0);
    		}
  	}
}


