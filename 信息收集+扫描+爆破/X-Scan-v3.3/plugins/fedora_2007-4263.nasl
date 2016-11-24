
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-4263
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(29278);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-4263: xorg-x11-xfs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-4263 (xorg-x11-xfs)");
 script_set_attribute(attribute: "description", value: "X.Org X11 xfs font server

-
References:

[ 1 ] Bug #373261 - CVE-2007-4568 xfs integer overflow in the build_range fun
ction [f7]
[9]https://bugzilla.redhat.com/show_bug.cgi?id=373261
[ 2 ] Bug #373331 - CVE-2007-4990 xfs heap overflow in the swap_char2b functi
on [f7]
[10]https://bugzilla.redhat.com/show_bug.cgi?id=373331
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-4568", "CVE-2007-4990");
script_summary(english: "Check for the version of the xorg-x11-xfs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xorg-x11-xfs-1.0.5-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
