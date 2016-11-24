
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-599
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25587);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2007-599: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-599 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

Merged stable kernel 2.6.20.12, 2.6.20.13, 2.6.20.14:
[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.12
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.13
[10]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.14

Added the latest GFS2 updates from the maintainers.

CVE-2007-2451:
Unspecified vulnerability in drivers/crypto/geode-aes.c
in GEODE-AES in the Linux kernel before 2.6.21.3 allows
attackers to obtain sensitive information via unspecified
vectors.

CVE-2007-2875:
Integer underflow in the cpuset_tasks_read function in the
Linux kernel before 2.6.20.13, and 2.6.21.x before 2.6.21.4,
when the cpuset filesystem is mounted, allows local users to
obtain kernel memory contents by using a large offset when
reading the /dev/cpuset/tasks file.

CVE-2007-2876:
Linux Kernel is prone to multiple weaknesses and
vulnerabilities that can allow remote attackers to carry out
various attacks, including denial-of-service attacks.

CVE-2007-2453:
The random number feature in Linux kernel 2.6 before 2.6.20.13,
and 2.6.21.x before 2.6.21.4, (1) does not properly seed pools
when there is no entropy, or (2) uses an incorrect cast when
extracting entropy, which might cause the random number
generator to provide the same values after reboots on systems
without an entropy source.

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-5757", "CVE-2007-0005", "CVE-2007-0006", "CVE-2007-0772", "CVE-2007-2451", "CVE-2007-2453", "CVE-2007-2875", "CVE-2007-2876");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.20-1.2320.fc5", prefix:"kernel-", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
