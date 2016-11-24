
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24810);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:060: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:060 (kernel).");
 script_set_attribute(attribute: "description", value: "Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel:
The 2.6.17 kernel and earlier, when running on IA64 and SPARC platforms
would allow a local user to cause a DoS (crash) via a malformed ELF file
(CVE-2006-4538).
The mincore function in the Linux kernel did not properly lock access to
user space, which has unspecified impact and attack vectors, possibly
related to a deadlock (CVE-2006-4814).
An unspecified vulnerability in the listxattr system call, when a 'bad
inode' is present, could allow a local user to cause a DoS (data
corruption) and possibly gain privileges via unknown vectors
(CVE-2006-5753).
The zlib_inflate function allows local users to cause a crash via a
malformed filesystem that uses zlib compression that triggers memory
corruption (CVE-2006-5823).
The ext3fs_dirhash function could allow local users to cause a DoS
(crash) via an ext3 stream with malformed data structures
(CVE-2006-6053).
When SELinux hooks are enabled, the kernel could allow a local user to
cause a DoS (crash) via a malformed file stream that triggers a NULL
pointer derefernece (CVE-2006-6056).
The key serial number collision avoidance code in the key_alloc_serial
function in kernels 2.6.9 up to 2.6.20 allows local users to cause a
crash via vectors thatr trigger a null dereference (CVE-2007-0006).
The Linux kernel version 2.6.13 to 2.6.20.1 allowed a remote attacker
to cause a DoS (oops) via a crafted NFSACL2 ACCESS request that
triggered a free of an incorrect pointer (CVE-2007-0772).
A local user could read unreadable binaries by using the interpreter
(PT_INTERP) functionality and triggering a core dump; a variant of
CVE-2004-1073 (CVE-2007-0958).
The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels immediately
and reboot to effect the fixes.
In addition to these security fixes, other fixes have been included
such as:
- add PCI IDs for cciss driver (HP ML370G5 / DL360G5)
- fixed a mssive SCSI reset on megasas (Dell PE2960)
- increased port-reset completion delay for HP controllers (HP ML350)
- NUMA rnage fixes for x86_64
- various netfilter fixes
To update your kernel, please follow the directions located at:
http://www.mandriva.com/en/security/kernelupdate
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:060");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-1073", "CVE-2006-4538", "CVE-2006-4814", "CVE-2006-5753", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6056", "CVE-2007-0006", "CVE-2007-0772", "CVE-2007-0958");
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

if ( rpm_check( reference:"kernel-2.6.12.31mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.6.12.31mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.12.31mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.12.31mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.12.31mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.12.31mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.12.31mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.12.31mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xbox-2.6.12.31mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen0-2.6.12.31mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.12.31mdk-1-1mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2004-1073", value:TRUE);
 set_kb_item(name:"CVE-2006-4538", value:TRUE);
 set_kb_item(name:"CVE-2006-4814", value:TRUE);
 set_kb_item(name:"CVE-2006-5753", value:TRUE);
 set_kb_item(name:"CVE-2006-5823", value:TRUE);
 set_kb_item(name:"CVE-2006-6053", value:TRUE);
 set_kb_item(name:"CVE-2006-6056", value:TRUE);
 set_kb_item(name:"CVE-2007-0006", value:TRUE);
 set_kb_item(name:"CVE-2007-0772", value:TRUE);
 set_kb_item(name:"CVE-2007-0958", value:TRUE);
}
exit(0, "Host is not affected");
