#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description) {
  script_id(15718);
  script_version ("$Revision: 1.5 $");
  script_cve_id("CVE-2004-1036");
  script_bugtraq_id(11653);
  script_xref(name:"OSVDB", value:"11603");

  script_name(english:"SquirrelMail decodeHeader HTML injection vulnerability");
  script_summary(english:"Check Squirrelmail for HTML injection vulnerability");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an information disclosure attack.'
  );

  script_set_attribute(
    attribute:'description',
    value:
'The remote host is running SquirrelMail, a webmail system written in PHP.

Versions of SquirrelMail prior to 1.4.4 are affected by an email HTML
injection issue.  A remote attacker can exploit this flaw to gain
access to the users\' accounts.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to the newest version of this software.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://article.gmane.org/gmane.mail.squirrelmail.user/21169'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2004-11/0129.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

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

    		if (ereg(pattern:"^(0\..*|1\.([0-3]\..*|4\.[0-3][^0-9]))$", string:ver))
		{
      			security_warning(port);
      			exit(0);
    		}
  	}
}
