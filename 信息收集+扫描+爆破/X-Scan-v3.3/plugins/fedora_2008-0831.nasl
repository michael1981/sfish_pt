
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-0831
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(30076);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2008-0831: xorg-x11-server");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-0831 (xorg-x11-server)");
 script_set_attribute(attribute: "description", value: "X.Org X11 X server

-
Update Information:

CVE-2007-5760: XFree86-Misc Extension Invalid Array Index Vulnerability
CVE-2007-5958: Xorg / XFree86 file existence disclosure vulnerability
CVE-2007-6427: XInput Extension Memory Corruption Vulnerability
CVE-2007-6428: TOG-CUP Extension Memory Corruption Vulnerability
CVE-2007-6429: EVI and MIT-SHM Extension Integer Overflow Vulnerability
CVE-2008-0006: PCF Font Vulnerability - this patch isn't strictly required with
new version of libXfont.

This contains ajax's fixes for the MITSHM patch.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0006");
script_summary(english: "Check for the version of the xorg-x11-server package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xorg-x11-server-1.3.0.0-15.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
