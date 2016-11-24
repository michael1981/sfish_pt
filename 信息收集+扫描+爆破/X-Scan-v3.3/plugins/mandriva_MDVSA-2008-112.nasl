
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36852);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:112: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:112 (kernel).");
 script_set_attribute(attribute: "description", value: "Some vulnerabilities were discovered and corrected in the Linux
2.6 kernel:
The Datagram Congestion Control Protocol (DCCP) subsystem in the
Linux kernel 2.6.18, and probably other versions, does not properly
check feature lengths, which might allow remote attackers to execute
arbitrary code, related to an unspecified overflow. (CVE-2008-2358)
VFS in the Linux kernel before 2.6.22.16, and 2.6.23.x before
2.6.23.14, performs tests of access mode by using the flag variable
instead of the acc_mode variable, which might allow local users to
bypass intended permissions and remove directories. (CVE-2008-0001)
Linux kernel before 2.6.22.17, when using certain drivers that register
a fault handler that does not perform range checks, allows local users
to access kernel memory via an out-of-range offset. (CVE-2008-0007)
Integer overflow in the hrtimer_start function in kernel/hrtimer.c
in the Linux kernel before 2.6.23.10 allows local users to execute
arbitrary code or cause a denial of service (panic) via a large
relative timeout value. NOTE: some of these details are obtained from
third party information. (CVE-2007-5966)
The shmem_getpage function (mm/shmem.c) in Linux kernel 2.6.11
through 2.6.23 does not properly clear allocated memory in some
rare circumstances related to tmpfs, which might allow local
users to read sensitive kernel data or cause a denial of service
(crash). (CVE-2007-6417)
The isdn_ioctl function in isdn_common.c in Linux kernel 2.6.23
allows local users to cause a denial of service via a crafted ioctl
struct in which iocts is not null terminated, which triggers a buffer
overflow. (CVE-2007-6151)
The do_coredump function in fs/exec.c in Linux kernel 2.4.x and 2.6.x
up to 2.6.24-rc3, and possibly other versions, does not change the
UID of a core dump file if it exists before a root process creates
a core dump in the same location, which might allow local users to
obtain sensitive information. (CVE-2007-6206)
Buffer overflow in the isdn_net_setcfg function in isdn_net.c in
Linux kernel 2.6.23 allows local users to have an unknown impact via
a crafted argument to the isdn_ioctl function. (CVE-2007-6063)
The wait_task_stopped function in the Linux kernel before 2.6.23.8
checks a TASK_TRACED bit instead of an exit_state value, which
allows local users to cause a denial of service (machine crash) via
unspecified vectors. NOTE: some of these details are obtained from
third party information. (CVE-2007-5500)
The minix filesystem code in Linux kernel 2.6.x before 2.6.24,
including 2.6.18, allows local users to cause a denial of service
(hang) via a malformed minix file stream that triggers an infinite
loop in the minix_bmap function. NOTE: this issue might be due to an
integer overflow or signedness error. (CVE-2006-6058)
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:112");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-6058", "CVE-2007-5500", "CVE-2007-5966", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6417", "CVE-2008-0001", "CVE-2008-0007", "CVE-2008-2358");
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

if ( rpm_check( reference:"kernel-2.6.17.19mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.17.19mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-latest-2.6.17-19mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.17.19mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-latest-2.6.17-19mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-latest-2.6.17-19mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-2.6.17.19mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-latest-2.6.17-19mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.17.19mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-latest-2.6.17-19mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.17.19mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-latest-2.6.17-19mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.17.19mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-latest-2.6.17-19mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.17.19mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-latest-2.6.17-19mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2006-6058", value:TRUE);
 set_kb_item(name:"CVE-2007-5500", value:TRUE);
 set_kb_item(name:"CVE-2007-5966", value:TRUE);
 set_kb_item(name:"CVE-2007-6063", value:TRUE);
 set_kb_item(name:"CVE-2007-6151", value:TRUE);
 set_kb_item(name:"CVE-2007-6206", value:TRUE);
 set_kb_item(name:"CVE-2007-6417", value:TRUE);
 set_kb_item(name:"CVE-2008-0001", value:TRUE);
 set_kb_item(name:"CVE-2008-0007", value:TRUE);
 set_kb_item(name:"CVE-2008-2358", value:TRUE);
}
exit(0, "Host is not affected");
