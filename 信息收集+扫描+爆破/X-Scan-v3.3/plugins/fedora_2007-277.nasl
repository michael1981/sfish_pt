
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-277
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24766);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2007-277: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-277 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

Updated to kernel 2.6.19.5-rc1 plus additional fixes:

[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.19.4

2.6.19.5-rc1:
4 V4L fixes
3 usbaudio fixes
3 wireless driver fixes
2 IDE driver cable detection fixes
NFS bugfix
various other fixes

CVE-2007-0772:
Summary: The Linux kernel before 2.6.20.1 allows remote
attackers to cause a denial of service (oops) via a crafted
NFSACL 2 ACCESS request that triggers a free of an incorrect
pointer.

CVE-2006-5753:
Summary: Unspecified vulnerability in the listxattr system
call in Linux kernel, when a 'bad inode' is present, allows
local users to cause a denial of service (data corruption)
and possibly gain privileges via unknown vectors.

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-5753", "CVE-2006-5757", "CVE-2007-0006", "CVE-2007-0772");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.19-1.2288.2.1.fc5", prefix:"kernel-", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
