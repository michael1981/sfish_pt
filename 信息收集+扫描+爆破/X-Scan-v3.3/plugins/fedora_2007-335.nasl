
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-335
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24823);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2007-335: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-335 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

Rebased to kernel 2.6.20.3-rc1:

[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.1
(The CVE fix in 2.6.20.1 is already in
kernel-2.6.19-1.2911.6.5.fc6.)
[10]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.2
Changelog for 2.6.20.3 is not available yet.

This release does not include Xen kernels.

CVE-2007-0005:
A vulnerability has been reported in the Linux Kernel, which
potentially can be exploited by malicious, local users to
cause a DoS (Denial of Service) or gain escalated privileges.

The vulnerability is caused due to boundary errors within
the 'read()' and 'write()' functions of the Omnikey CardMan
4040 driver. This can be exploited to cause a buffer
overflow and may allow the execution of arbitrary code with
kernel privileges.

CVE-2007-1000:
A vulnerability has been reported in the Linux Kernel, which
can be exploited by malicious, local users to cause a DoS
(Denial of Service) or disclose potentially sensitive
information.

The vulnerability is due to a NULL pointer dereference
within the 'ipv6_getsockopt_sticky()' function in
net/ipv6/ipv6_sockglue.c. This can be exploited to crash the
kernel or disclose kernel memory.

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-0005", "CVE-2007-1000");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.20-1.2925.fc6", prefix:"kernel-", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
