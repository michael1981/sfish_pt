
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14049);
 script_version ("$Revision: 1.9 $");
 script_name(english: "MDKSA-2003:066-2: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:066-2 (kernel).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities were discovered and fixed in the Linux kernel.
* CVE-2003-0001: Multiple ethernet network card drivers do not pad
frames with null bytes which allows remote attackers to obtain
information from previous packets or kernel memory by using
special malformed packets.
* CVE-2003-0244: The route cache implementation in the 2.4 kernel and
the Netfilter IP conntrack module allows remote attackers to cause a
Denial of Service (DoS) via CPU consumption due to packets with
forged source addresses that cause a large number of hash table
collisions related to the PREROUTING chain.
* CVE-2003-0246: The ioperm implementation in 2.4.20 and earlier
kernels does not properly restrict privileges, which allows local
users to gain read or write access to certain I/O ports.
* CVE-2003-0247: A vulnerability in the TTY layer of the 2.4 kernel
allows attackers to cause a kernel oops resulting in a DoS.
* CVE-2003-0248: The mxcsr code in the 2.4 kernel allows attackers to
modify CPU state registers via a malformed address.
* CVE-2003-0462: A file read race existed in the execve() system call.
As well, a number of bug fixes were made in the 9.1 kernel including:
* Support for more machines that did not work with APIC
* Audigy2 support
* New/updated modules: prims25, adiusbadsl, thinkpad, ieee1394,
orinoco, via-rhine,
* Fixed SiS IOAPIC
* IRQ balancing has been fixed for SMP
* Updates to ext3
* The previous ptrace fix has been redone to work better
* Bugs with compiling kernels using xconfig have been fixed
* Problems with ipsec have been corrected
* XFS ACLs are now present
* gdb not working on XFS root filesystems has been fixed
MandrakeSoft encourages all users to upgrade to these new kernels.
Updated kernels will be available shortly for other supported platforms
and architectures.
For full instructions on how to properly upgrade your kernel, please
review http://www.mandrakesecure.net/en/docs/magic.php.
Update:
The kernels provided in MDKSA-2003:066-1 (2.4.21-0.24mdk) had a problem
where all files created on any filesystem other than XFS, and using any
kernel other than kernel-secure, would be created with mode 0666, or
world writeable. The 0.24mdk kernels have been removed from the
mirrors and users are encouraged to upgrade and remove those kernels
from their systems to prevent accidentally booting into them.
That issue has been addressed and fixed with these new kernels.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:066-2");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0001", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248", "CVE-2003-0462");
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

if ( rpm_check( reference:"kernel-2.4.21.0.25mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21.0.25mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-0.25mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.21.0.25mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.21.0.25mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21.0.25mdk-1-1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-0.25mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0001", value:TRUE);
 set_kb_item(name:"CVE-2003-0244", value:TRUE);
 set_kb_item(name:"CVE-2003-0246", value:TRUE);
 set_kb_item(name:"CVE-2003-0247", value:TRUE);
 set_kb_item(name:"CVE-2003-0248", value:TRUE);
 set_kb_item(name:"CVE-2003-0462", value:TRUE);
}
exit(0, "Host is not affected");
