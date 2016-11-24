
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-712
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(26116);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 6 2007-712: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-712 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

Update to official Linux 2.6.22.6 (previously 2.6.22.6-rc1):
[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.22.6

Update to Linux 2.6.22.7:
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.22.7

- USB: three trivial fixes
- futex: fix compat list traversal
- Restore ofpath functionality (IDE_PROC_FS=y)(#289931)
- add option to disable DMA on libata PATA devices
(libata.pata_dma, see kernel-parameters.txt)
- fix DMA on ATAPI devices with it821x
- fix cable detection on pata_via
- fix vmware's broken SCSI device emulation
- fix init of huawei 220 modem
- LVM: fix hang and lockups during snapshot (#269541)
- net: fix oops with zero-length packet (#253290)
- CFS scheduler updates
- utrace update (#248532, #267161, #284311)

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

if ( rpm_check( reference:"kernel-2.6.22.7-57.fc6", prefix:"kernel-", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
