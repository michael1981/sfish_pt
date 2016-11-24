
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2721
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27798);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-2721: xscreensaver");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2721 (xscreensaver)");
 script_set_attribute(attribute: "description", value: "A modular screen saver and locker for the X Window System.
More than 200 display modes are included in this package.

This is a metapackage for installing all default packages
related to XScreenSaver.

-
Update Information:

Related to bug 336331, another case is found which causes xscreensaver password
dialog crash. This time a patch from upstream developer is applied and this re
lease 'really' fixes this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5585");
script_summary(english: "Check for the version of the xscreensaver package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xscreensaver-5.03-14.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
