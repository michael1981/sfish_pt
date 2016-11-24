
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-5893
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33404);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-5893: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-5893 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

-
Update Information:

Update kernel from version 2.6.25.6 to 2.6.25.9:
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.7
[10]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.8
[11]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.9    Security
updates:  CVE-2008-2750: The pppol2tp_recvmsg function in drivers/net/pppol2tp.
c
in the Linux kernel 2.6 before 2.6.26-rc6 allows remote attackers to cause a
denial of service (kernel heap memory corruption and system crash) and possibly
have unspecified other impact via a crafted PPPOL2TP packet that results in a
large value for a certain length variable.    CVE-2008-2358: The Datagram
Congestion Control Protocol (DCCP) subsystem in the Linux kernel 2.6.18, and
probably other versions, does not properly check feature lengths, which might
allow remote attackers to execute arbitrary code, related to an unspecified
'overflow.'    Wireless driver updates:  - Upstream wireless fixes from
2008-06-27    ([12]http://marc.info/?l=linux-wireless&m=121459423021061&w=2)  -
Upstream wireless fixes from 2008-06-25    ([13]http://marc.info/?l=linux-
wireless&m=121440912502527&w=2)  - Upstream wireless updates from 2008-06-14
([14]http://marc.info/?l=linux-netdev&m=121346686508160&w=2)  - Upstream wirele
ss
fixes from 2008-06-09    ([15]http://marc.info/?l=linux-
kernel&m=121304710726632&w=2)  - Upstream wireless updates from 2008-06-09
([16]http://marc.info/?l=linux-netdev&m=121304710526613&w=2)    Bugs:  444694 -
ALi
Corporation M5253 P1394 OHCI 1.1 Controller driver causing problems in kernels
newer than 2.6.24.3-50  452595 - Problem with SATA/IDE on Abit AN52  449080 -
Rsync cannot copy to a vfat partition on kernel 2.6.25 with -p or -a options
449909 - User Mode Linux (UML) broken on Fedora 9  452111 - CVE-2008-2750
kernel: l2tp: Fix potential memory corruption in pppol2tp-recvmsg() (Heap
corruption DoS) [F9]  449872 - [Patch] Bluetooth keyboard not reconnecting afte
r
powersave
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2358", "CVE-2008-2750");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.25.9-76.fc9", prefix:"kernel-", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
