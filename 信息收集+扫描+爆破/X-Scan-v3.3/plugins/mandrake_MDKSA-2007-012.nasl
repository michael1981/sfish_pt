
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24628);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:012: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:012 (kernel).");
 script_set_attribute(attribute: "description", value: "Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel:
The __block_prepate_write function in the 2.6 kernel before 2.6.13 does
not properly clear buffers during certain error conditions, which
allows users to read portions of files that have been unlinked
(CVE-2006-4813).
The clip_mkip function of the ATM subsystem in the 2.6 kernel allows
remote attackers to dause a DoS (panic) via unknown vectors that cause
the ATM subsystem to access the memory of socket buffers after they are
freed (CVE-2006-4997).
The NFS lockd in the 2.6 kernel before 2.6.16 allows remote attackers
to cause a DoS (process crash) and deny access to NFS exports via
unspecified vectors that trigger a kernel oops and a deadlock
(CVE-2006-5158).
The seqfile handling in the 2.6 kernel up to 2.6.18 allows local users
to cause a DoS (hang or oops) via unspecified manipulations that
trigger an infinite loop while searching for flowlabels
(CVE-2006-5619).
A missing call to init_timer() in the isdn_ppp code of the Linux kernel
can allow remote attackers to send a special kind of PPP pakcet which
may trigger a kernel oops (CVE-2006-5749).
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
- __bread oops fix
- added e1000_ng (nineveh support)
- added sata_svw (Broadcom SATA support)
- added Marvell PATA chipset support
- disabled mmconf on some broken hardware/BIOSes
- use GENERICARCH and enable bigsmp apic model for tulsa machines
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:012");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4813", "CVE-2006-4997", "CVE-2006-5158", "CVE-2006-5619", "CVE-2006-5749", "CVE-2006-5751", "CVE-2006-5757", "CVE-2006-6106");
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

if ( rpm_check( reference:"kernel-2.6.12.29mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.6.12.29mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.12.29mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.12.29mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.12.29mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.12.29mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.12.29mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.12.29mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xbox-2.6.12.29mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.12.29mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.12.29mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-4813", value:TRUE);
 set_kb_item(name:"CVE-2006-4997", value:TRUE);
 set_kb_item(name:"CVE-2006-5158", value:TRUE);
 set_kb_item(name:"CVE-2006-5619", value:TRUE);
 set_kb_item(name:"CVE-2006-5749", value:TRUE);
 set_kb_item(name:"CVE-2006-5751", value:TRUE);
 set_kb_item(name:"CVE-2006-5757", value:TRUE);
 set_kb_item(name:"CVE-2006-6106", value:TRUE);
}
exit(0, "Host is not affected");
