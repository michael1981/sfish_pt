
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24653);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:040: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:040 (kernel).");
 script_set_attribute(attribute: "description", value: "Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel:
The isdn_ppp_ccp_reset_alloc_state function in drivers/isdn/isdn_ppp.c
in the Linux 2.4 kernel before 2.4.34-rc4, as well as the 2.6 kernel,
does not call the init_timer function for the ISDN PPP CCP reset state
timer, which has unknown attack vectors and results in a system crash.
(CVE-2006-5749)
The listxattr syscall can corrupt user space under certain
circumstances. The problem seems to be related to signed/unsigned
conversion during size promotion. (CVE-2006-5753)
The ext3fs_dirhash function in Linux kernel 2.6.x allows local users to
cause a denial of service (crash) via an ext3 stream with malformed
data structures. (CVE-2006-6053)
The mincore function in the Linux kernel before 2.4.33.6, as well as
the 2.6 kernel, does not properly lock access to user space, which has
unspecified impact and attack vectors, possibly related to a deadlock.
(CVE-2006-4814)
The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels immediately
and reboot to effect the fixes.
In addition to these security fixes, other fixes have been included
such as:
- Add Ralink RT2571W/RT2671 WLAN USB support (rt73 module) - Fix
sys_msync() to report -ENOMEM as before when an unmapped area falls
within its range, and not to overshoot (LSB regression) - Avoid disk
sector_t overflow for >2TB ext3 filesystem - USB: workaround to fix HP
scanners detection (#26728) - USB: unusual_devs.h for Sony floppy
(#28378) - Add preliminary ICH9 support - Add TI sd card reader
support - Add RT61 driver - KVM update - Fix bttv vbi offset
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:040");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4814", "CVE-2006-5749", "CVE-2006-5753", "CVE-2006-6053");
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

if ( rpm_check( reference:"kernel-2.6.17.10mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.17.10mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.17.10mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-legacy-2.6.17.10mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.17.10mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.17.10mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.17.10mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.17.10mdv-1-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-4814", value:TRUE);
 set_kb_item(name:"CVE-2006-5749", value:TRUE);
 set_kb_item(name:"CVE-2006-5753", value:TRUE);
 set_kb_item(name:"CVE-2006-6053", value:TRUE);
}
exit(0, "Host is not affected");
