
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-424
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25027);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2007-424: xorg-x11-server");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-424 (xorg-x11-server)");
 script_set_attribute(attribute: "description", value: "X.Org X11 X server



Update information :

* Sun Apr  8 2007 Adam Jackson <ajax redhat com> 1.0.1-9.fc5.7
- xserver-cve-2007-1003.patch: Fix CVE 2007-1003 in XC-MISC extension.
- xorg-x11-server-1.0.1-intel-bridge-fix.patch: Backport an Intel PCI bridge
fix from FC6.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-1526");
script_summary(english: "Check for the version of the xorg-x11-server package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xorg-x11-server-1.0.1-9.fc5.7", release:"FC5") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
