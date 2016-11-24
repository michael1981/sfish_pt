
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24567);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:182: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:182 (kernel).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered and corrected in the Linux
2.6 kernel:
Stephane Eranian discovered an issue with permon2.0 where, under
certain circumstances, the perfmonctl() system call may not correctly
manage the file descriptor reference count, resulting in the system
possibly running out of file structure (CVE-2006-3741).
Prior to and including 2.6.17, the Universal Disk Format (UDF)
filesystem driver allowed local users to cause a DoS (hang and crash)
via certain operations involving truncated files (CVE-2006-4145).
Various versions of the Linux kernel allowed local users to cause a DoS
(crash) via an SCTP socket with a certain SO_LINGER value, which is
possibly related to the patch used to correct CVE-2006-3745
(CVE-2006-4535).
The Unidirectional Lightweight Encapsulation (ULE) decapsulation
component in the dvb driver allows remote attackers to cause a DoS
(crash) via an SNDU length of 0 in a ULE packet (CVE-2006-4623).
The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels immediately
and reboot to effect the fixes.
In addition to these security fixes, other fixes have been included
such as:
- added support for new devices: o NetXtreme BCM5715 gigabit ethernet o
NetXtreme II BCM5708 gigabit ethernet - enabled the CISS driver for Xen
kernels - updated ich8 support in ata_piix - enabled support for 1078
type controller in megaraid_sas - multiple fixes for RSBAC support
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:182");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-3741", "CVE-2006-3745", "CVE-2006-4145", "CVE-2006-4535", "CVE-2006-4623");
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

if ( rpm_check( reference:"kernel-2.6.12.27mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.6.12.27mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.12.27mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.12.27mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.12.27mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.12.27mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.12.27mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xbox-2.6.12.27mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.12.27mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.12.27mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"librsbac1-1.2.4-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"librsbac1-devel-1.2.4-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"librsbac1-static-devel-1.2.4-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rsbac-admin-1.2.4-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rsbac-admin-doc-1.2.4-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xen-3.0.1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-3741", value:TRUE);
 set_kb_item(name:"CVE-2006-3745", value:TRUE);
 set_kb_item(name:"CVE-2006-4145", value:TRUE);
 set_kb_item(name:"CVE-2006-4535", value:TRUE);
 set_kb_item(name:"CVE-2006-4623", value:TRUE);
}
exit(0, "Host is not affected");
