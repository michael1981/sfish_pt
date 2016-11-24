
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18599);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:111: kernel-2.4");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:111 (kernel-2.4).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities in the Linux kernel have been discovered and
fixed in this update. The following have been fixed in the 2.4
kernels:
Colin Percival discovered a vulnerability in Intel's Hyper-Threading
technology could allow a local user to use a malicious thread to create
covert channels, monitor the execution of other threads, and obtain
sensitive information such as cryptographic keys via a timing attack on
memory cache misses. This has been corrected by disabling HT support
in all kernels (CVE-2005-0109).
When forwarding fragmented packets, a hardware assisted checksum could
only be used once which could lead to a Denial of Service attack or
crash by remote users (CVE-2005-0209).
A flaw in the Linux PPP driver was found where on systems allowing
remote users to connect to a server via PPP, a remote client could
cause a crash, resulting in a Denial of Service (CVE-2005-0384).
An information leak in the ext2 filesystem code was found where when a
new directory is created, the ext2 block written to disk is not
initialized (CVE-2005-0400).
A signedness error in the copy_from_read_buf function in n_tty.c
allows local users to read kernel memory via a negative argument
(CVE-2005-0530).
George Guninski discovered a buffer overflow in the ATM driver
where the atm_get_addr() function does not validate its arguments
sufficiently which could allow a local attacker to overwrite large
portions of kernel memory by supplying a negative length argument. This
could potentially lead to the execution of arbitrary code
(CVE-2005-0531).
A flaw when freeing a pointer in load_elf_library was found that could
be abused by a local user to potentially crash the machine causing a
Denial of Service (CVE-2005-0749).
A problem with the Bluetooth kernel stack in kernels 2.4.6 through
2.4.30-rc1 and 2.6 through 2.6.11.5 could be used by a local attacker
to gain root access or crash the machine (CVE-2005-0750).
A race condition in the Radeon DRI driver allows a local user with DRI
privileges to execute arbitrary code as root (CVE-2005-0767).
Paul Starzetz found an integer overflow in the ELF binary format
loader's code dump function in kernels prior to and including 2.4.31-pre1
and 2.6.12-rc4. By creating and executing a specially
crafted ELF executable, a local attacker could exploit this to
execute arbitrary code with root and kernel privileges
(CVE-2005-1263).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:111");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0109", "CVE-2005-0209", "CVE-2005-0384", "CVE-2005-0400", "CVE-2005-0530", "CVE-2005-0531", "CVE-2005-0749", "CVE-2005-0750", "CVE-2005-0767", "CVE-2005-1263");
script_summary(english: "Check for the version of the kernel-2.4 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kernel-2.4.25.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.25.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.4.25.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-p3-smp-64GB-2.4.25.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.25.14mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.25-14mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.28.0.rc1.6mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.28.0.rc1.6mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.4.28.0.rc1.6mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.28.0.rc1.6mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4-2.4.28-0.rc1.6mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-2.4-", release:"MDK10.0")
 || rpm_exists(rpm:"kernel-2.4-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0109", value:TRUE);
 set_kb_item(name:"CVE-2005-0209", value:TRUE);
 set_kb_item(name:"CVE-2005-0384", value:TRUE);
 set_kb_item(name:"CVE-2005-0400", value:TRUE);
 set_kb_item(name:"CVE-2005-0530", value:TRUE);
 set_kb_item(name:"CVE-2005-0531", value:TRUE);
 set_kb_item(name:"CVE-2005-0749", value:TRUE);
 set_kb_item(name:"CVE-2005-0750", value:TRUE);
 set_kb_item(name:"CVE-2005-0767", value:TRUE);
 set_kb_item(name:"CVE-2005-1263", value:TRUE);
}
exit(0, "Host is not affected");
