
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2270
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27763);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-2270: xen");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2270 (xen)");
 script_set_attribute(attribute: "description", value: "This package contains the Xen hypervisor and Xen tools, needed to
run virtual machines on x86 systems, together with the kernel-xen*
packages.  Information on how to use Xen can be found at the Xen
project pages.

Virtualisation can be used to run multiple versions or multiple
Linux distributions on one system, or to test untrusted applications
in a sandboxed environment.

-
Update Information:

Fixes a security flaw in pygrub handling of config files and a denial-of-servic
e case in ne2k NIC for QEMU.

Fixes the case of disappearing network cards in fully-virtualized guests. NB, i
t only fixes it for guests created after this errata is installed & XenD restar
ted. Any pre-existing guests may continue to have problems. To fix existing gue
sts, first ensure XenD has been restarted (service xend restart), then use virt
-manager/virsh to remove the network card, and then add it back. This will corr
ect the configuration stored in XenD permanently.

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-1321", "CVE-2007-4993");
script_summary(english: "Check for the version of the xen package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xen-3.1.0-6.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
