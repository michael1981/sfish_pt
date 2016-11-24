
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-10439
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42125);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-10439: dopewars");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-10439 (dopewars)");
 script_set_attribute(attribute: "description", value: "Based on John E. Dell's old Drug Wars game, dopewars is a simulation of an
imaginary drug market. dopewars is an All-American game which features
buying, selling, and trying to get past the cops!

The first thing you need to do is pay off your debt to the Loan Shark. After
that, your goal is to make as much money as possible (and stay alive)! You
have one month of game time to make your fortune.

dopewars supports multiple players via. TCP/IP. Chatting to and fighting
with other players (computer or human) is supported; check the command line
switches (via dopewars -h) for further information.

-
Update Information:

Fix DoS.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-3591");
script_summary(english: "Check for the version of the dopewars package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"dopewars-1.5.12-8.1033svn.fc11", release:"FC11") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
