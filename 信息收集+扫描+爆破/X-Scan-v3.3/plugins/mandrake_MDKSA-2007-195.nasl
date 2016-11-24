
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27561);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDKSA-2007:195: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:195 (kernel).");
 script_set_attribute(attribute: "description", value: "Some vulnerabilities were discovered and corrected in the Linux
2.6 kernel:
A stack-based buffer overflow in the random number generator could
allow local root users to cause a denial of service or gain privileges
by setting the default wakeup threshold to a value greater than the
output pool size (CVE-2007-3105).
The lcd_write function did not limit the amount of memory used by
a caller, which allows local users to cause a denial of service
(memory consumption) (CVE-2007-3513).
The decode_choice function allowed remote attackers to cause a denial
of service (crash) via an encoded out-of-range index value for a choice
field which triggered a NULL pointer dereference (CVE-2007-3642).
The Linux kernel allowed local users to send arbitrary signals
to a child process that is running at higher privileges by
causing a setuid-root parent process to die which delivered an
attacker-controlled parent process death signal (PR_SET_PDEATHSIG)
(CVE-2007-3848).
The aac_cfg_openm and aac_compat_ioctl functions in the SCSI layer
ioctl patch in aacraid did not check permissions for ioctls, which
might allow local users to cause a denial of service or gain privileges
(CVE-2007-4308).
The IA32 system call emulation functionality, when running on the
x86_64 architecture, did not zero extend the eax register after the
32bit entry path to ptrace is used, which could allow local users to
gain privileges by triggering an out-of-bounds access to the system
call table using the %RAX register (CVE-2007-4573).
In addition to these security fixes, other fixes have been included
such as:
- More NVidia PCI ids wre added
- The 3w-9xxx module was updated to version 2.26.02.010
- Fixed the map entry for ICH8
- Added the TG3 5786 PCI id
- Reduced the log verbosity of cx88-mpeg
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:195");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-3105", "CVE-2007-3513", "CVE-2007-3642", "CVE-2007-3848", "CVE-2007-4308", "CVE-2007-4573");
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

if ( rpm_check( reference:"kernel-2.6.17.16mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.17.16mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.17.16mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-2.6.17.16mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.17.16mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.17.16mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.17.16mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.17.16mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.17.16mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.17.16mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-latest-2.6.17-16mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.17.16mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-latest-2.6.17-16mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-latest-2.6.17-16mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-2.6.17.16mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-latest-2.6.17-16mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.17.16mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-latest-2.6.17-16mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.17.16mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-latest-2.6.17-16mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.17.16mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-latest-2.6.17-16mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.17.16mdv-1-1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-latest-2.6.17-16mdv", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2007.0")
 || rpm_exists(rpm:"kernel-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-3105", value:TRUE);
 set_kb_item(name:"CVE-2007-3513", value:TRUE);
 set_kb_item(name:"CVE-2007-3642", value:TRUE);
 set_kb_item(name:"CVE-2007-3848", value:TRUE);
 set_kb_item(name:"CVE-2007-4308", value:TRUE);
 set_kb_item(name:"CVE-2007-4573", value:TRUE);
}
exit(0, "Host is not affected");
