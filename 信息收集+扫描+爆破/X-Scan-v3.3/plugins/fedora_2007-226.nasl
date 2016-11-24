
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-226
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24349);
 script_version ("$Revision: 1.5 $");
script_name(english: "Fedora 6 2007-226: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-226 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

CVE-2006-0007:
The key serial number collision avoidance code in the
key_alloc_serial function in Linux kernel 2.6.9 up to 2.6.20
allows remote attackers to cause a denial of service (crash)
via vectors that trigger a null dereference, as originally
reported as 'spinlock CPU recursion.'

Update to linux kernel 2.6.19.3:
www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.19.3

Bugs fixed:
227802, 226885, 225046, 223431

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-0007", "CVE-2007-0006");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.19-1.2911.fc6", prefix:"kernel-", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
