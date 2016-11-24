
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-4043
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32384);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-4043: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-4043 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

-
Update Information:

Update to Linux kernel version 2.6.23.17:
[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.16
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.23.17    Additiona
lly,
following security fixes were backported:  CVE-2008-1669  - SMP ordering hole i
n
fcntl_setlk()  CVE-2008-1615  - Denial-of-service on x86_64 architecture.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5938", "CVE-2008-0600", "CVE-2008-1615", "CVE-2008-1669");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.23.17-88.fc7", prefix:"kernel-", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
