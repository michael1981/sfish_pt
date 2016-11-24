
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1130
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27691);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1130: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1130 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

-
Update Information:

Rebase kernel to 2.6.22.1:
[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.22
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.22.1

Includes the CFS scheduler from upstream kernel 2.6.23.

Users should update to the latest autofs package with this kernel or autofs wil
l use excessive amounts of CPU time.

CVE-2007-3642:
The decode_choice function in net/netfilter/bf_conntrack_h323_asn1.c in the Lin
ux kernel before 2.6.22 allows remote attackers to cause a denial of service (c
rash) via an encoded, out-of-range index value for a choice field, which trigge
rs a NULL pointer dereference.


");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3642");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.22.1-27.fc7", prefix:"kernel-", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
