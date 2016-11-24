
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36924);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:044: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:044 (kernel).");
 script_set_attribute(attribute: "description", value: "The wait_task_stopped function in the Linux kernel before 2.6.23.8
checks a TASK_TRACED bit instead of an exit_state value, which
allows local users to cause a denial of service (machine crash) via
unspecified vectors. NOTE: some of these details are obtained from
third party information. (CVE-2007-5500)
The tcp_sacktag_write_queue function in the Linux kernel 2.6.21 through
2.6.23.7 allowed remote attackers to cause a denial of service (crash)
via crafted ACK responses that trigger a NULL pointer dereference
(CVE-2007-5501).
The do_corefump function in fs/exec.c in the Linux kernel prior to
2.6.24-rc3 did not change the UID of a core dump file if it exists
before a root process creates a core dump in the same location, which
could possibly allow local users to obtain sensitive information
(CVE-2007-6206).
VFS in the Linux kernel before 2.6.22.16 performed tests of access
mode by using the flag variable instead of the acc_mode variable,
which could possibly allow local users to bypass intended permissions
and remove directories (CVE-2008-0001).
The Linux kernel prior to 2.6.22.17, when using certain drivers
that register a fault handler that does not perform range checks,
allowed local users to access kernel memory via an out-of-range offset
(CVE-2008-0007).
A flaw in the vmsplice system call did not properly verify address
arguments passed by user-space processes, which allowed local
attackers to overwrite arbitrary kernel memory and gain root privileges
(CVE-2008-0600).
Mandriva urges all users to upgrade to these new kernels immediately
as the CVE-2008-0600 flaw is being actively exploited. This issue
only affects 2.6.17 and newer Linux kernels, so neither Corporate
3.0 nor Corporate 4.0 are affected.
Additionally, this kernel updates the version from 2.6.22.12 to
2.6.22.18 and fixes numerous other bugs, including:
- fix freeze when ejecting a cm40x0 PCMCIA card
- fix crash on unloading netrom
- fixes alsa-related sound issues on Dell XPS M1210 and M1330 models
- the HZ value was increased on the laptop kernel to increase
interactivity and reduce latency
- netfilter ipset, psd, and ifwlog support was re-enabled
- unionfs was reverted to a working 1.4 branch that is less buggy
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:044");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-5500", "CVE-2007-5501", "CVE-2007-6206", "CVE-2008-0001", "CVE-2008-0007", "CVE-2008-0600");
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

if ( rpm_check( reference:"kernel-2.6.22.18-1mdv-1-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-2.6.22.18-1mdv-1-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-devel-2.6.22.18-1mdv-1-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-devel-latest-2.6.22.18-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop-latest-2.6.22.18-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-2.6.22.18-1mdv-1-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-devel-2.6.22.18-1mdv-1-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-devel-latest-2.6.22.18-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-desktop586-latest-2.6.22.18-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.22.18-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-laptop-2.6.22.18-1mdv-1-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-laptop-devel-2.6.22.18-1mdv-1-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-laptop-devel-latest-2.6.22.18-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-laptop-latest-2.6.22.18-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-2.6.22.18-1mdv-1-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-devel-2.6.22.18-1mdv-1-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-devel-latest-2.6.22.18-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-server-latest-2.6.22.18-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.22.18-1mdv-1-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-latest-2.6.22.18-1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2007-5500", value:TRUE);
 set_kb_item(name:"CVE-2007-5501", value:TRUE);
 set_kb_item(name:"CVE-2007-6206", value:TRUE);
 set_kb_item(name:"CVE-2008-0001", value:TRUE);
 set_kb_item(name:"CVE-2008-0007", value:TRUE);
 set_kb_item(name:"CVE-2008-0600", value:TRUE);
}
exit(0, "Host is not affected");
