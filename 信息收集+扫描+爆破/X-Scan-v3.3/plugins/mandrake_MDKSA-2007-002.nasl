
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24619);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:002: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:002 (kernel).");
 script_set_attribute(attribute: "description", value: "Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel:
The Linux kernel does not properly save or restore EFLAGS during a
context switch, or reset the flags when creating new threads, which
could allow a local user to cause a Denial of Service (process crash)
(CVE-2006-5173).
The seqfile handling in the 2.6 kernel up to 2.6.18 allows local users
to cause a DoS (hang or oops) via unspecified manipulations that
trigger an infinite loop while searching for flowlabels
(CVE-2006-5619).
An integer overflow in the 2.6 kernel prior to 2.6.18.4 could allow a
local user to execute arbitrary code via a large maxnum value in an
ioctl request (CVE-2006-5751).
A race condition in the ISO9660 filesystem handling could allow a local
user to cause a DoS (infinite loop) by mounting a crafted ISO9660
filesystem containing malformed data structures (CVE-2006-5757).
A vulnerability in the bluetooth support could allow for overwriting
internal CMTP and CAPI data structures via malformed packets
(CVE-2006-6106).
The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels immediately
and reboot to effect the fixes.
In addition to these security fixes, other fixes have been included
such as:
- added the marvell IDE driver - use a specific driver Jmicron chipsets
rather than using a generic one - updated the sky2 driver to fix some
network hang issues
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:002");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-5173", "CVE-2006-5619", "CVE-2006-5751", "CVE-2006-5757", "CVE-2006-6106");
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

if ( rpm_check( reference:"kernel-2.6.17.8mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.17.8mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-2.6.17.8mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.17.8mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.17.8mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.17.8mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.17.8mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-5173", value:TRUE);
 set_kb_item(name:"CVE-2006-5619", value:TRUE);
 set_kb_item(name:"CVE-2006-5751", value:TRUE);
 set_kb_item(name:"CVE-2006-5757", value:TRUE);
 set_kb_item(name:"CVE-2006-6106", value:TRUE);
}
exit(0, "Host is not affected");
