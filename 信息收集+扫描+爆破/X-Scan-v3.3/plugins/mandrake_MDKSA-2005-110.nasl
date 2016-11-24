
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18598);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:110: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:110 (kernel).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities in the Linux kernel have been discovered and
fixed in this update. The following CVE names have been fixed in the
LE2005 kernel:
Colin Percival discovered a vulnerability in Intel's Hyper-Threading
technology could allow a local user to use a malicious thread to create
covert channels, monitor the execution of other threads, and obtain
sensitive information such as cryptographic keys via a timing attack on
memory cache misses. This has been corrected by disabling HT support
in all kernels (CVE-2005-0109).
An information leak in the ext2 filesystem code in kernels prior to
2.6.11.6 was found where when a new directory is created, the ext2
block written to disk is not initialized (CVE-2005-0400).
A flaw when freeing a pointer in load_elf_library was found in kernels
prior to 2.6.11.6 that could be abused by a local user to potentially
crash the machine causing a Denial of Service (CVE-2005-0749).
A problem with the Bluetooth kernel stack in kernels 2.4.6 through
2.4.30-rc1 and 2.6 through 2.6.11.5 could be used by a local attacker
to gain root access or crash the machine (CVE-2005-0750).
Paul Starzetz found an integer overflow in the ELF binary format
loader's code dump function in kernels prior to and including 2.4.31-pre1
and 2.6.12-rc4. By creating and executing a specially
crafted ELF executable, a local attacker could exploit this to
execute arbitrary code with root and kernel privileges
(CVE-2005-1263).
The drivers for raw devices used the wrong function to pass arguments
to the underlying block device in 2.6.x kernels. This made the kernel
address space accessible to user-space applictions allowing any local
user with at least read access to a device in /dev/raw/* (usually only
root) to execute arbitrary code with kernel privileges (CVE-2005-1264).
The it87 and via686a hardware monitor drivers in kernels prior to
2.6.11.8 and 2.6.12 prior to 2.6.12-rc2 created a sysfs file named
'alarms' with write permissions although they are not designed to be
writable. This allowed a local user to crash the kernel by attempting
to write to these files (CVE-2005-1369).
In addition to the above-noted CVE-2005-0109, CVE-2005-0400,
CVE-2005-0749, CVE-2005-0750, and CVE-2005-1369 fixes, the following
CVE names have been fixed in the 10.1 kernel:
The POSIX Capability Linux Security Module (LSM) for 2.6 kernels up to
and including 2.6.8.1 did not properly handle the credentials of a
process that is launched before the module is loaded, which could be
used by local attackers to gain elevated privileges (CVE-2004-1337).
A flaw in the Linux PPP driver in kernel 2.6.8.1 was found where on
systems allowing remote users to connect to a server via PPP, a remote
client could cause a crash, resulting in a Denial of Service
(CVE-2005-0384).
George Guninski discovered a buffer overflow in the ATM driver in
kernels 2.6.10 and 2.6.11 before 2.6.11-rc4 where the atm_get_addr()
function does not validate its arguments sufficiently which could allow
a local attacker to overwrite large portions of kernel memory by
supplying a negative length argument. This could potentially lead to
the execution of arbitrary code (CVE-2005-0531).
The reiserfs_copy_from_user_to_file_region function in reiserfs/file.c
before kernel 2.6.11, when running on 64-bit architectures, could allow
local users to trigger a buffer overflow as a result of casting
discrepancies between size_t and int data types. This could allow an
attacker to overwrite kernel memory, crash the machine, or potentially
obtain root access (CVE-2005-0532).
A race condition in the Radeon DRI driver in kernel 2.6.8.1 allows a
local user with DRI privileges to execute arbitrary code as root
(CVE-2005-0767).
Access was not restricted to the N_MOUSE discipline for a TTY in
kernels prior to 2.6.11. This could allow local attackers to obtain
elevated privileges by injecting mouse or keyboard events into other
user's sessions (CVE-2005-0839).
Some futex functions in futex.c in 2.6 kernels performed get_user calls
while holding the mmap_sem semaphore, which could allow a local
attacker to cause a deadlock condition in do_page_fault by triggering
get_user faults while another thread is executing mmap or other
functions (CVE-2005-0937).
In addition to the above-noted CVE-2004-1337, CVE-2005-0109,
CVE-2005-0384, CVE-2005-0400, CVE-2005-0531, CVE-2005-0532,
CVE-2005-0749, CVE-2005-0750, CVE-2005-0767, CVE-2005-0839,
CVE-2005-0937, CVE-2005-1263, CVE-2005-1264, and CVE-2005-1369
fixes, the following CVE names have been fixed in the 10.0/
Corporate 3.0 kernels:
A race condition in the setsid function in kernels before 2.6.8.1 could
allow a local attacker to cause a Denial of Service and possibly access
portions of kernel memory related to TTY changes, locking, and
semaphores (CVE-2005-0178).
When forwarding fragmented packets in kernel 2.6.8.1, a hardware
assisted checksum could only be used once which could lead to a Denial
of Service attack or crash by remote users (CVE-2005-0209).
A signedness error in the copy_from_read_buf function in n_tty.c
before kernel 2.6.11 allows local users to read kernel memory via a
negative argument (CVE-2005-0530).
A vulnerability in the fib_seq_start() function allowed a local user
to crash the system by readiung /proc/net/route in a certain way,
causing a Denial of Service (CVE-2005-1041).
A vulnerability in the Direct Rendering Manager (DRM) driver in the
2.6 kernel does not properly check the DMA lock, which could allow
remote attackers or local users to cause a Denial of Service (X Server
crash) and possibly modify the video output (CVE-2004-1056).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:110");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-1056", "CVE-2004-1337", "CVE-2005-0109", "CVE-2005-0178", "CVE-2005-0209", "CVE-2005-0384", "CVE-2005-0400", "CVE-2005-0530", "CVE-2005-0531", "CVE-2005-0532", "CVE-2005-0749", "CVE-2005-0750", "CVE-2005-0767", "CVE-2005-0839", "CVE-2005-0937", "CVE-2005-1041", "CVE-2005-1263", "CVE-2005-1264", "CVE-2005-1369");
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

if ( rpm_check( reference:"kernel-2.6.3.27mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.3.27mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.3.27mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-p3-smp-64GB-2.6.3.27mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.6.3.27mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.3.27mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.3-27mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.3-27mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.8.1.25mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.8.1.25mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.8.1.25mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-64GB-2.6.8.1.25mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.6.8.1.25mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.8.1.25mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6-2.6.8.1-25mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6-2.6.8.1-25mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.11.12mdk-1-1mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.11.12mdk-1-1mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.11.12mdk-1-1mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.11.12mdk-1-1mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6-2.6.11-12mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6-2.6.11-12mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xbox-2.6.11.12mdk-1-1mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK10.0")
 || rpm_exists(rpm:"kernel-", release:"MDK10.1")
 || rpm_exists(rpm:"kernel-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2004-1056", value:TRUE);
 set_kb_item(name:"CVE-2004-1337", value:TRUE);
 set_kb_item(name:"CVE-2005-0109", value:TRUE);
 set_kb_item(name:"CVE-2005-0178", value:TRUE);
 set_kb_item(name:"CVE-2005-0209", value:TRUE);
 set_kb_item(name:"CVE-2005-0384", value:TRUE);
 set_kb_item(name:"CVE-2005-0400", value:TRUE);
 set_kb_item(name:"CVE-2005-0530", value:TRUE);
 set_kb_item(name:"CVE-2005-0531", value:TRUE);
 set_kb_item(name:"CVE-2005-0532", value:TRUE);
 set_kb_item(name:"CVE-2005-0749", value:TRUE);
 set_kb_item(name:"CVE-2005-0750", value:TRUE);
 set_kb_item(name:"CVE-2005-0767", value:TRUE);
 set_kb_item(name:"CVE-2005-0839", value:TRUE);
 set_kb_item(name:"CVE-2005-0937", value:TRUE);
 set_kb_item(name:"CVE-2005-1041", value:TRUE);
 set_kb_item(name:"CVE-2005-1263", value:TRUE);
 set_kb_item(name:"CVE-2005-1264", value:TRUE);
 set_kb_item(name:"CVE-2005-1369", value:TRUE);
}
exit(0, "Host is not affected");
