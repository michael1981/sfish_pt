
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-499
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24096);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2006-499: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-499 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

An update to the latest upstream -stable snapshot (2.6.16.13)

Among quite a few bug-fixes, are two security related fixes:

Don't allow a backslash in a path component  (CVE-2006-1863)
NETFILTER: SCTP conntrack: fix infinite loop (CVE-2006-1527)

Detailed changelogs of the last few point releases can be
found at:

[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.10
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.11
[10]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.12
[11]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.16.13

Fedora specific changelog detailed below.

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-1527", "CVE-2006-1863");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.16-1.2107_FC5", prefix:"kernel-", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
