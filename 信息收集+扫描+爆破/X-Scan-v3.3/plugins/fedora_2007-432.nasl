
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-432
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25047);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 6 2007-432: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-432 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

Updated to upstream linux kernel 2.6.20.6:
[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.5
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.6

CVE-2007-1357:
The atalk_sum_skb function in AppleTalk for Linux kernel
2.6.x before 2.6.21, and possibly 2.4.x, allows remote
attackers to cause a denial of service (crash) via an
AppleTalk frame that is shorter than the specified length,
which triggers a BUG_ON call when an attempt is made to
perform a checksum.

CVSS Severity: 3.3 (Low)


Plus additional fixes:
Bugfix for ATI SB600 SATA
Routing bugfix
Libata LBA48 bugfix
Update libata NCQ blacklist
Libata request sense bugfix
SCSI error handler fix

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-1357");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.20-1.2944.fc6", prefix:"kernel-", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
