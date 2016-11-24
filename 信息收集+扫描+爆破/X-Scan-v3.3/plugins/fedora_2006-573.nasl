
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-573
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24110);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 4 2006-573: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-573 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

This update rebases to the latest upstream -stable release
(2.6.16.17), where a number of security problems have been
fixed, notably:

SCTP: Validate the parameter length in HB-ACK chunk
(CVE-2006-1857)
SCTP: Respect the real chunk length when walking parameters
(CVE-2006-1858)
fs/locks.c: Fix lease_init (CVE-2006-1860)
SCTP: Fix state table entries for chunks received in CLOSED
state. (CVE-2006-2271)
SCTP: Fix panic's when receiving fragmented SCTP control
chunks. (CVE-2006-2272)
SCTP: Prevent possible infinite recursion with multiple
bundled DATA. (CVE-2006-2274)
SCTP: Allow spillover of receive buffer to avoid deadlock.
(CVE-2006-2275)


Complete changelogs for the -stable releases can be found at

[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.17
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.16
[10]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.15

Fedora specific changes are detailed below
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-1857", "CVE-2006-1858", "CVE-2006-1860", "CVE-2006-2271", "CVE-2006-2272", "CVE-2006-2274", "CVE-2006-2275");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.16-1.2111_FC4", prefix:"kernel-", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
