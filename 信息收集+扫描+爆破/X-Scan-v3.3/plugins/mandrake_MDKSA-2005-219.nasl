
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20450);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2005:219: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:219 (kernel).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities in the Linux 2.6 kernel have been discovered
and corrected in this update:
An integer overflow in vc_resize (CVE-2004-1333).
A race condition in the sysfs_read_file and sysfs_write_file functions
in 2.6.10 and earlier allows local users to read kernel memory and
cause a DoS (crash) via large offsets in sysfs files (CVE-2004-2302).
An integer signedness error in scsi_ioctl.c (CVE-2005-0180).
Netfilter allows a local user to cause a DoS (memory consumption) via
certain packet fragments that are reassembled twice, which causes a
data structure to be allocated twice (CVE-2005-0210).
A DoS in pkt_ioctl in pktcdvc.c (CVE-2005-1589).
An array index overflow in the xfrm_sk_policy_insert function in
xfrm_user.c allows local users to cause a DoS (oops or deadlock) and
possibly execute arbitrary code (CVE-2005-2456).
The zisofs driver in versions prior to 2.6.12.5 allows local users and
remove attackers to cause a DoS (crash) via a crafted compressed ISO
filesystem (CVE-2005-2457).
inflate.c in the zlib routines in versions prior to 2.6.12.5 allow
remove attackers to cause a DoS (crash) via a compressed file with
'improper tables' (CVE-2005-2458).
The huft_build function in inflate.c in the zlib routines in versions
prior to 2.6.12.5 returns the wrong value, allowing remote attackers to
cause a DoS (crash) via a certain compressed file that leads to a null
pointer dereference (CVE-2005-2459).
A stack-based buffer overflow in the sendmsg function call in versions
prior to 2.6.13.1 allow local users to execute arbitrary code by
calling sendmsg and modifying the message contents in another thread
(CVE-2005-2490).
vlan_dev.c in version 2.6.8 allows remote attackers to cause a DoS
(oops from null dereference) via certain UDP packets that lead to
a function call with the wrong argument (CVE-2005-2548).
The kernel does not properly restrict socket policy access to users
with the CAP_NET_ADMIN capability, which could allow local users to
conduct unauthorized activities via ipv4/ip_sockglue.c and
ipv6/ipv6_sockglue.c (CVE-2005-2555).
A memory leak in the seq_file implementation in the SCSI procfs
interface (sg.c) in 2.6.13 and earlier allows a local user to cause a
DoS (memory consumption) via certain repeated reads from
/proc/scsi/gs/devices file which is not properly handled when the
next() interator returns NULL or an error (CVE-2005-2800).
xattr.c in the ext2 and ext3 file system code does not properly compare
the name_index fields when sharing xattr blocks which could prevent
ACLs from being applied (CVE-2005-2801).
The ipt_recent module in versions prior to 2.6.12 when running on 64bit
processors allows remote attackers to cause a DoS (kernel panic) via
certain attacks such as SSH brute force (CVE-2005-2872).
The ipt_recent module in versions prior to 2.6.12 does not properly
perform certain tests when the jiffies value is greater than LONG_MAX,
which can cause ipt_recent netfilter rules to block too early
(CVE-2005-2873).
Multiple vulnerabilities in versions prior to 2.6.13.2 allow local
users to cause a DoS (oops from null dereference) via fput in a 32bit
ioctl on 64-bit x86 systems or sockfd_put in the 32-bit routing_ioctl
function on 64-bit systems (CVE-2005-3044).
The sys_set_mempolicy function in mempolicy.c allows local users to
cause a DoS via a negative first argument (CVE-2005-3053).
Versions 2.6.8 to 2.6.14-rc2 allow local users to cause a DoS (oops)
via a userspace process that issues a USB Request Block (URB) to a USB
device and terminates before the URB is finished, which leads to a
stale pointer reference (CVE-2005-3055).
The Orinoco driver in 2.6.13 and earlier does not properly clear memory
from a previously used packet whose length is increased, allowing
remote attackers to obtain sensitive information (CVE-2005-3180).
Kernels 2.6.13 and earlier, when CONFIG_AUDITSYSCALL is enabled, use an
incorrect function to free names_cache memory, preventing the memory
from being tracked by AUDITSYSCALL code and leading to a memory leak
(CVE-2005-3181).
The VT implementation in version 2.6.12 allows local users to use
certain IOCTLs on terminals of other users and gain privileges
(CVE-2005-3257).
Exec does not properly clear posix-timers in multi-threaded
environments, which result in a resource leak and could allow a large
number of multiple local users to cause a DoS by using more posix-
timers than specified by the quota for a single user (CVE-2005-3271).
The rose_rt_ioctl function rose_route.c in versions prior to 2.6.12
does not properly verify the ndigis argument for a new route, allowing
an attacker to trigger array out-of-bounds errors with a large number
of digipeats (CVE-2005-3273).
A race condition in ip_vs_conn_flush in versions prior to 2.6.13, when
running on SMP systems, allows local users to cause a DoS (null
dereference) by causing a connection timer to expire while the
connection table is being flushed before the appropriate lock is
acquired (CVE-2005-3274).
The NAT code in versions prior to 2.6.13 incorrectly declares a
variable to be static, allowing remote attackers to cause a DoS (memory
corruption) by causing two packets for the same protocol to be NATed at
the same time (CVE-2005-3275).
The sys_get_thread_area function in process.c in versions prior to
2.6.12.4 and 2.6.13 does not clear a data structure before copying it
to userspace, which may allow a user process to obtain sensitive
information (CVE-2005-3276).
The following non-security fixes are also applied:
Driver updates were made to the aic97xx and sata_sil modules.
Support was added for ATI ipx400 chipsets, for IDE and sound.
A build problem with icecream on the x86_64 platform was fixed.
The pin1 APIC timer on RS480-based motherboards was disabled.
The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels.
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:219");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-1333", "CVE-2004-2302", "CVE-2005-0180", "CVE-2005-0210", "CVE-2005-1589", "CVE-2005-2456", "CVE-2005-2457", "CVE-2005-2458", "CVE-2005-2459", "CVE-2005-2490", "CVE-2005-2548", "CVE-2005-2555", "CVE-2005-2800", "CVE-2005-2801", "CVE-2005-2872", "CVE-2005-2873", "CVE-2005-3044", "CVE-2005-3053", "CVE-2005-3055", "CVE-2005-3180", "CVE-2005-3181", "CVE-2005-3257", "CVE-2005-3271", "CVE-2005-3273", "CVE-2005-3274", "CVE-2005-3275", "CVE-2005-3276");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kernel-2.6.8.1.26mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.8.1.26mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.8.1.26mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-64GB-2.6.8.1.26mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.6.8.1.26mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.8.1.26mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6-2.6.8.1-26mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6-2.6.8.1-26mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1333", value:TRUE);
 set_kb_item(name:"CVE-2004-2302", value:TRUE);
 set_kb_item(name:"CVE-2005-0180", value:TRUE);
 set_kb_item(name:"CVE-2005-0210", value:TRUE);
 set_kb_item(name:"CVE-2005-1589", value:TRUE);
 set_kb_item(name:"CVE-2005-2456", value:TRUE);
 set_kb_item(name:"CVE-2005-2457", value:TRUE);
 set_kb_item(name:"CVE-2005-2458", value:TRUE);
 set_kb_item(name:"CVE-2005-2459", value:TRUE);
 set_kb_item(name:"CVE-2005-2490", value:TRUE);
 set_kb_item(name:"CVE-2005-2548", value:TRUE);
 set_kb_item(name:"CVE-2005-2555", value:TRUE);
 set_kb_item(name:"CVE-2005-2800", value:TRUE);
 set_kb_item(name:"CVE-2005-2801", value:TRUE);
 set_kb_item(name:"CVE-2005-2872", value:TRUE);
 set_kb_item(name:"CVE-2005-2873", value:TRUE);
 set_kb_item(name:"CVE-2005-3044", value:TRUE);
 set_kb_item(name:"CVE-2005-3053", value:TRUE);
 set_kb_item(name:"CVE-2005-3055", value:TRUE);
 set_kb_item(name:"CVE-2005-3180", value:TRUE);
 set_kb_item(name:"CVE-2005-3181", value:TRUE);
 set_kb_item(name:"CVE-2005-3257", value:TRUE);
 set_kb_item(name:"CVE-2005-3271", value:TRUE);
 set_kb_item(name:"CVE-2005-3273", value:TRUE);
 set_kb_item(name:"CVE-2005-3274", value:TRUE);
 set_kb_item(name:"CVE-2005-3275", value:TRUE);
 set_kb_item(name:"CVE-2005-3276", value:TRUE);
}
exit(0, "Host is not affected");
