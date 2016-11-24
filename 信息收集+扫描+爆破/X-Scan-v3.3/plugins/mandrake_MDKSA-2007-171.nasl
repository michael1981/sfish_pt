
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25968);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:171: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:171 (kernel).");
 script_set_attribute(attribute: "description", value: "Some vulnerabilities were discovered and corrected in the Linux
2.6 kernel:
The Linux kernel did not properly save or restore EFLAGS during a
context switch, or reset the flags when creating new threads, which
allowed local users to cause a denial of service (process crash)
(CVE-2006-5755).
The compat_sys_mount function in fs/compat.c allowed local users
to cause a denial of service (NULL pointer dereference and oops)
by mounting a smbfs file system in compatibility mode (CVE-2006-7203).
The nfnetlink_log function in netfilter allowed an attacker to cause a
denial of service (crash) via unspecified vectors which would trigger
a NULL pointer dereference (CVE-2007-1496).
The nf_conntrack function in netfilter did not set nfctinfo during
reassembly of fragmented packets, which left the default value as
IP_CT_ESTABLISHED and could allow remote attackers to bypass certain
rulesets using IPv6 fragments (CVE-2007-1497).
The netlink functionality did not properly handle NETLINK_FIB_LOOKUP
replies, which allowed a remote attacker to cause a denial of service
(resource consumption) via unspecified vectors, probably related to
infinite recursion (CVE-2007-1861).
A typo in the Linux kernel caused RTA_MAX to be used as an array size
instead of RTN_MAX, which lead to an out of bounds access by certain
functions (CVE-2007-2172).
The IPv6 protocol allowed remote attackers to cause a denial of
service via crafted IPv6 type 0 route headers that create network
amplification between two routers (CVE-2007-2242).
The random number feature did not properly seed pools when there was
no entropy, or used an incorrect cast when extracting entropy, which
could cause the random number generator to provide the same values
after reboots on systems without an entropy source (CVE-2007-2453).
A memory leak in the PPPoE socket implementation allowed local users
to cause a denial of service (memory consumption) by creating a
socket using connect, and releasing it before the PPPIOCGCHAN ioctl
is initialized (CVE-2007-2525).
An integer underflow in the cpuset_tasks_read function, when the cpuset
filesystem is mounted, allowed local users to obtain kernel memory
contents by using a large offset when reading the /dev/cpuset/tasks
file (CVE-2007-2875).
The sctp_new function in netfilter allowed remote attackers to cause
a denial of service by causing certain invalid states that triggered
a NULL pointer dereference (CVE-2007-2876).
In addition to these security fixes, other fixes have been included
such as:
- Fix crash on netfilter when nfnetlink_log is used on certain
hooks on packets forwarded to or from a bridge
- Fixed busy sleep on IPVS which caused high load averages
- Fixed possible race condition on ext[34]_link
- Fixed missing braces in condition block that led to wrong behaviour
in NFS
- Fixed XFS lock deallocation that resulted in oops when unmounting
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:171");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-5755", "CVE-2006-7203", "CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1861", "CVE-2007-2172", "CVE-2007-2242", "CVE-2007-2453", "CVE-2007-2525", "CVE-2007-2875", "CVE-2007-2876");
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

if ( rpm_check( reference:"kernel-2.6.17.15mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.17.15mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.17.15mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-2.6.17.15mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.17.15mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.17.15mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.17.15mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.17.15mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.17.15mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.17.15mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-latest-2.6.17-15mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.17.15mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-latest-2.6.17-15mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-latest-2.6.17-15mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-2.6.17.15mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-latest-2.6.17-15mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.17.15mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-latest-2.6.17-15mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.17.15mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-latest-2.6.17-15mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.17.15mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-latest-2.6.17-15mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.17.15mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-latest-2.6.17-15mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2007.0")
 || rpm_exists(rpm:"kernel-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2006-5755", value:TRUE);
 set_kb_item(name:"CVE-2006-7203", value:TRUE);
 set_kb_item(name:"CVE-2007-1496", value:TRUE);
 set_kb_item(name:"CVE-2007-1497", value:TRUE);
 set_kb_item(name:"CVE-2007-1861", value:TRUE);
 set_kb_item(name:"CVE-2007-2172", value:TRUE);
 set_kb_item(name:"CVE-2007-2242", value:TRUE);
 set_kb_item(name:"CVE-2007-2453", value:TRUE);
 set_kb_item(name:"CVE-2007-2525", value:TRUE);
 set_kb_item(name:"CVE-2007-2875", value:TRUE);
 set_kb_item(name:"CVE-2007-2876", value:TRUE);
}
exit(0, "Host is not affected");
