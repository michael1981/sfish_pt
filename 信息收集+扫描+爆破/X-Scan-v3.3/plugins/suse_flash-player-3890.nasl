
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29434);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for flash-player (flash-player-3890)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch flash-player-3890");
 script_set_attribute(attribute: "description", value: "The Adobe Flash Player was updated to version 7.0.70.0 for
Novell Linux Desktop 9 and to version 9.0.48.0 on SUSE
Linux Enterprise Desktop 10 to fix several security
problems:

CVE-2007-3456: An input validation error has been
identified in Flash Player 9.0.45.0 and earlier versions
that could lead to the potential execution of arbitrary
code.  This vulnerability could be accessed through content
delivered from a remote location via the user's web
browser, email client, or other applications that include
or reference the Flash Player.

CVE-2007-3457: An issue with insufficient validation of the
HTTP Referer has been identified in Flash Player 8.0.34.0
and earlier. This issue does not affect Flash Player 9.
This issue could potentially aid an attacker in executing a
cross-site request forgery attack.

CVE-2007-2022: The Linux and Solaris updates for Flash
Player 7 (7.0.70.0) address the issues with Flash Player
and the Opera and Konqueror browsers described in Security
Advisory APSA07-03. These issues do not impact Flash Player
9 on Linux or Solaris.

The affected webbrowsers Opera and konqueror have already
been fixed independendly.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch flash-player-3890");
script_end_attributes();

script_cve_id("CVE-2007-2022", "CVE-2007-3456", "CVE-2007-3457");
script_summary(english: "Check for the flash-player-3890 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"flash-player-9.0.48.0-1.2", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
