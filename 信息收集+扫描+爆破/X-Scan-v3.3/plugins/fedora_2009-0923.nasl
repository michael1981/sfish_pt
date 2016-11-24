
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-0923
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38129);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-0923: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-0923 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

-
Update Information:

Update to kernel 2.6.27.12:
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.10
[10]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.11
[11]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.12    Includes
security fixes:  CVE-2009-0029 Linux Kernel insecure 64 bit system call argumen
t
passing  CVE-2009-0065 kernel: sctp: memory overflow when FWD-TSN chunk is
received with bad stream ID    Reverts ALSA driver to the version that is
upstream in kernel 2.6.27.    This should be the last 2.6.27 kernel update for
Fedora 10.  A 2.6.28 update kernel is being tested.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5079", "CVE-2009-0029", "CVE-2009-0065");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.27.12-170.2.5.fc10", prefix:"kernel-", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
