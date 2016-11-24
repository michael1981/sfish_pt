
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9397
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40990);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 11 2009-9397: kdepim-runtime");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9397 (kdepim-runtime)");
 script_set_attribute(attribute: "description", value: "KDE PIM Runtime Environment

-
Update Information:

This updates KDE to 4.3.1, the latest upstream bugfix release. The main
improvements are:  * KDE 4.3 is now also available in Croatian.  * A crash when
editing toolbar setup has been fixed.  * Support for transferring files through
SSH using KIO::Fish has been fixed.  * A number of bugs in KWin, KDE's window
and compositing manager has been fixed.  * A large number of bugs in KMail,
KDE's email client are now gone.    See
[9]http://kde.org/announcements/announce-4.3.1.php for more information.    In
addition, this update:  * fixes a potential security issue (CVE-2009-2702) with
certificate validation in the KIO KSSL code. It is believed that the affected
code is not actually used (the code in Qt, for which a security update was
already issued, is) and thus the issue is only potential, but KSSL is being
patched just in case,  * splits PolicyKit-kde out of kdebase-workspace again to
avoid forcing it onto GNOME-based setups, where PolicyKit-gnome is desired
instead (#519654).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-2702");
script_summary(english: "Check for the version of the kdepim-runtime package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kdepim-runtime-4.3.1-1.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
