#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#
# References:
# Date:  Mon, 11 Mar 2002 12:46:06 +0700
# From: "Fyodor" <fyarochkin@trusecure.com>
# To: bugtraq@securityfocus.com
# Subject: SunSolve CD cgi scripts...
#
# Date: Sat, 16 Jun 2001 23:24:45 +0700
# From: Fyodor <fyodor@relaygroup.com>
# To: security-alert@sun.com
# Subject: SunSolve CD security problems..
#

include( 'compat.inc' );

if(description)
{
  script_id(11066);
  script_version("$Revision: 1.13 $");
  script_cve_id("CVE-2002-0436");
  script_bugtraq_id(4269);
  script_xref(name:"OSVDB", value:"10598");

  script_name(english:"Sun Sunsolve CD Pack sscd_suncourier.pl email Parameter Arbitrary Command Execution");
  script_summary(english:"SunSolve CD CGI scripts are vulnerable to a few user input validation problems");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to injection attacks allowing command execution.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The Sunsolve CD is part of the Solaris Media pack. It is included
as a documentation resource, and is available for the Solaris Operating Environment.

Sunsolve CD CGI scripts does not validate user input.
Crackers may use them to execute some commands on your system.

** Note: Nessus did not try to perform the attack.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Do not use the SunSolve CD.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2002-03/0139.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
  );

  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("find_service1.nasl", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 8383);
  exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:8383);

if (is_cgi_installed_ka(port: port, item:"/cd-cgi/sscd_suncourier.pl")) {
	security_hole(port);
	exit(0);
}

if (is_cgi_installed_ka(port: port, item:"sscd_suncourier.pl")) {
	security_hole(port);
	exit(0);
}
