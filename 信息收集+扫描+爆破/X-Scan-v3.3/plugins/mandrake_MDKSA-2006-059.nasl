
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21133);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:059: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:059 (kernel).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered and corrected in the Linux
2.6 kernel:
sysctl.c in the Linux kernel prior to 2.6.14.1 allows local users to
cause a Denial of Service (kernel oops) and possibly execute code by
opening an interface file in /proc/sys/net/ipv4/conf/, waiting until
the interface is unregistered, then obtaining and modifying function
pointers in memory that was used for the ctl_table (CVE-2005-2709).
Multiple vulnerabilities in versions prior to 2.6.13.2 allow local
users to cause a DoS (oops from null dereference) via fput in a 32bit
ioctl on 64-bit x86 systems or sockfd_put in the 32-bit routing_ioctl
function on 64-bit systems (CVE-2005-3044). Note that this was
previously partially corrected in MDKSA-2005:235.
Prior to 2.6.14, the kernel's atm module allows local users to cause a
DoS (panic) via certain socket calls that produce inconsistent reference
counts for loadable protocol modules (CVE-2005-3359).
A race condition in the (1) add_key, (2) request_key, and (3) keyctl
functions in the 2.6.x kernel allows local users to cause a DoS (crash)
or read sensitive kernel memory by modifying the length of a string
argument between the time that the kernel calculates the length and
when it copies the data into kernel memory (CVE-2006-0457).
Prior to 2.6.15.5, the kernel allows local users to obtain sensitive
information via a crafted XFS ftruncate call, which may return stale
data (CVE-2006-0554).
Prior to 2.6.15.5, the kernel allows local users to cause a DoS (NFS
client panic) via unknown attack vectors related to the use of O_DIRECT
(CVE-2006-0555).
Prior to an including kernel 2.6.16, sys_mbind in mempolicy.c does not
sanity check the maxnod variable before making certain computations,
which has an unknown impact and attack vectors (CVE-2006-0557).
Prior to 2.6.15.5, the kernel allows local users to cause a DoS
('endless recursive fault') via unknown attack vectors related to a
'bad elf entry address' on Intel processors (CVE-2006-0741).
Prior to 2.6.15.6, the die_if_kernel function in the kernel can allow
local users to cause a DoS by causing user faults on Itanium systems
(CVE-2006-00742).
A race in the signal-handling code which allows a process to become
unkillable when the race is triggered was also fixed.
In addition to these security fixes, other fixes have been included
such as:
- add ich8 support
- libata locking rewrite
- libata clear ATA_QCFLAG_ACTIVE flag before calling the completion
callback
- support the Acer Aspire 5xxx/3xxx series in the acerhk module
- USB storage: remove info sysfs file as it violates the sysfs one
value per file rule
- fix OOPS in sysfs_hash_and_remove_file()
- pl2303 USB driver fixes; makes pl2303HX chip work correctly
- fix OOPS in IPMI driver which is probably caused when trying to use
ACPI functions when ACPI was not properly initialized
- fix de_thread() racy BUG_ON()
The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels.
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
Please note that users using the LSI Logic 53c1030 dual-channel ultra
320 SCSI card will need to re-create their initrd images manually
prior to rebooting in order to fix a bug that prevents booting. A
future update will correct this problem. To do this, execute:
# rm /boot/initrd-2.6.12-18mdk.img
# mkinitrd /boot/initrd-2.6.12-18mdk.img 2.6.12-18mdk --with-module=mptspi
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:059");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-2709", "CVE-2005-3044", "CVE-2005-3359", "CVE-2006-0074", "CVE-2006-0457", "CVE-2006-0554", "CVE-2006-0555", "CVE-2006-0557", "CVE-2006-0741", "CVE-2006-0742");
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

if ( rpm_check( reference:"kernel-2.6.12.18mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.6.12.18mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.12.18mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.12.18mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.12.18mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6-2.6.12-18mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6-2.6.12-18mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xbox-2.6.12.18mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.12.18mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.12.18mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2709", value:TRUE);
 set_kb_item(name:"CVE-2005-3044", value:TRUE);
 set_kb_item(name:"CVE-2005-3359", value:TRUE);
 set_kb_item(name:"CVE-2006-0074", value:TRUE);
 set_kb_item(name:"CVE-2006-0457", value:TRUE);
 set_kb_item(name:"CVE-2006-0554", value:TRUE);
 set_kb_item(name:"CVE-2006-0555", value:TRUE);
 set_kb_item(name:"CVE-2006-0557", value:TRUE);
 set_kb_item(name:"CVE-2006-0741", value:TRUE);
 set_kb_item(name:"CVE-2006-0742", value:TRUE);
}
exit(0, "Host is not affected");
