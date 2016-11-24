
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-769
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24138);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 4 2006-769: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-769 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

An update to the latest upstream stable release (2.6.17.3),
which fixes a security issue with SCTP.

Further details:
[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.17.3
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.17.2

");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.17-1.2141_FC4", prefix:"kernel-", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
