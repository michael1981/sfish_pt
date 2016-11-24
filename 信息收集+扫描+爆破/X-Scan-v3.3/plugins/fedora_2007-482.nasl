
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-482
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25127);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2007-482: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-482 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

Linux kernel 2.6.20.7
[6]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.7
Previous kernel had most of this update already applied.

Linux kernel 2.6.20.8
[7]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.8
Fixes CVE-2007-1861

Linux kernel 2.6.20.9
[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.9
Fixes CVE-2007-2242

Linux kernel 2.6.20.10
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.10
Fixes two bugs introduced by the two previous updates.

CVE-2007-1861:
The netlink protocol has an infinite recursion bug that
allows users to cause a kernel crash.

CVE-2007-2242:
The IPv6 protocol allows remote attackers to cause a denial
of service via crafted IPv6 type 0 route headers
(IPV6_RTHDR_TYPE_0) that create network amplification
between two routers.


");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-1861", "CVE-2007-2242");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.20-1.2948.fc6", prefix:"kernel-", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
