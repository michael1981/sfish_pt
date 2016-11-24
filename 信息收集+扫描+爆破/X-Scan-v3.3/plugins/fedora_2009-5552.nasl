
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-5552
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38995);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-5552: pidgin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-5552 (pidgin)");
 script_set_attribute(attribute: "description", value: "Pidgin allows you to talk to anyone using a variety of messaging
protocols including AIM, MSN, Yahoo!, Jabber, Bonjour, Gadu-Gadu,
ICQ, IRC, Novell Groupwise, QQ, Lotus Sametime, SILC, Simple and
Zephyr.  These protocols are implemented using a modular, easy to
use design.  To use a protocol, just add an account using the
account editor.

Pidgin supports many common features of other clients, as well as many
unique features, such as perl scripting, TCL scripting and C plugins.

Pidgin is not affiliated with or endorsed by America Online, Inc.,
Microsoft Corporation, Yahoo! Inc., or ICQ Inc.

-
Update Information:

This is a bugfix & security fix release of Pidgin.    The full ChangeLog is
available at [9]http://developer.pidgin.im/wiki/ChangeLog    Details of the
security fixes included are available at [10]http://www.pidgin.im/news/security
/
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2927", "CVE-2009-1373", "CVE-2009-1374", "CVE-2009-1375");
script_summary(english: "Check for the version of the pidgin package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"pidgin-2.5.6-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
