
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16259);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:022: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:022 (kernel).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities are fixed in the 2.4 and 2.6 kernels with
this advisory:
- Multiple race conditions in the terminal layer of 2.4 and 2.6
kernels (prior to 2.6.9) can allow a local attacker to obtain
portions of kernel data or allow remote attackers to cause a kernel
panic by switching from console to PPP line discipline, then quickly
sending data that is received during the switch (CVE-2004-0814)
- Richard Hart found an integer underflow problem in the iptables
firewall logging rules that can allow a remote attacker to crash the
machine by using a specially crafted IP packet. This is only
possible, however, if firewalling is enabled. The problem only
affects 2.6 kernels and was fixed upstream in 2.6.8 (CVE-2004-0816)
- Stefan Esser found several remote DoS confitions in the smbfs file
system. This could be exploited by a hostile SMB server (or an
attacker injecting packets into the network) to crash the client
systems (CVE-2004-0883 and CVE-2004-0949)
- Paul Starzetz and Georgi Guninski reported, independantly, that bad
argument handling and bad integer arithmetics in the IPv4 sendmsg
handling of control messages could lead to a local attacker crashing
the machine. The fixes were done by Herbert Xu (CVE-2004-1016)
- Rob Landley discovered a race condition in the handling of
/proc/.../cmdline where, under rare circumstances, a user could read
the environment variables of another process that was still spawning
leading to the potential disclosure of sensitive information such as
passwords (CVE-2004-1058)
- Paul Starzetz reported that the missing serialization in
unix_dgram_recvmsg() which was added to kernel 2.4.28 can be used by
a local attacker to gain elevated (root) privileges (CVE-2004-1068)
- Ross Kendall Axe discovered a possible kernel panic (DoS) while
sending AF_UNIX network packets if certain SELinux-related kernel
options were enabled. By default the CONFIG_SECURITY_NETWORK and
CONFIG_SECURITY_SELINUX options are not enabled (CVE-2004-1069)
- Paul Starzetz of isec.pl discovered several issues with the error
handling of the ELF loader routines in the kernel. The fixes were
provided by Chris Wright (CVE-2004-1070, CVE-2004-1071,
CVE-2004-1072, CVE-2004-1073)
- It was discovered that hand-crafted a.out binaries could be used to
trigger a local DoS condition in both the 2.4 and 2.6 kernels. The
fixes were done by Chris Wright (CVE-2004-1074)
- Paul Starzetz found bad handling in the IGMP code which could lead
to a local attacker being able to crash the machine. The fix was
done by Chris Wright (CVE-2004-1137)
- Jeremy Fitzhardinge discovered two buffer overflows in the
sys32_ni_syscall() and sys32_vm86_warning() functions that could be
used to overwrite kernel memory with attacker-supplied code resulting
in privilege escalation (CVE-2004-1151)
- Paul Starzetz found locally exploitable flaws in the binary format
loader's uselib() function that could be abused to allow a local
user to obtain root privileges (CVE-2004-1235)
- Paul Starzetz found an exploitable flaw in the page fault handler
when running on SMP machines (CVE-2005-0001)
- A vulnerability in insert_vm_struct could allow a locla user to
trigger BUG() when the user created a large vma that overlapped with
arg pages during exec (CVE-2005-0003)
- Paul Starzetz also found a number of vulnerabilities in the kernel
binfmt_elf loader that could lead a local user to obtain elevated
(root) privileges (isec-0017-binfmt_elf)
The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels.
To update your kernel, please follow the directions located at:
http://www.mandrakesoft.com/security/kernelupdate
PLEASE NOTE: Mandrakelinux 10.0 users will need to upgrade to the
latest module-init-tools package prior to upgrading their kernel.
Likewise, MNF8.2 users will need to upgrade to the latest modutils
package prior to upgrading their kernel.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:022");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0814", "CVE-2004-0816", "CVE-2004-0883", "CVE-2004-0949", "CVE-2004-1016", "CVE-2004-1057", "CVE-2004-1058", "CVE-2004-1068", "CVE-2004-1069", "CVE-2004-1070", "CVE-2004-1071", "CVE-2004-1072", "CVE-2004-1073", "CVE-2004-1074", "CVE-2004-1137", "CVE-2004-1151", "CVE-2004-1235", "CVE-2005-0001", "CVE-2005-0003");
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

if ( rpm_check( reference:"kernel-2.4.25.13mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.3.25mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.25.13mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.3.25mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.4.25.13mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.6.3.25mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-p3-smp-64GB-2.4.25.13mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-p3-smp-64GB-2.6.3.25mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.6.3.25mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.25.13mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.3.25mdk-1-1mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.25-13mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.3-25mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6.3-25mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"module-init-tools-3.0-1.2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.28.0.rc1.5mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.8.1.24mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.28.0.rc1.5mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.6.8.1.24mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.4.28.0.rc1.5mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i586-up-1GB-2.6.8.1.24mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-64GB-2.6.8.1.24mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.6.8.1.24mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.28.0.rc1.5mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.8.1.24mdk-1-1mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4-2.4.28-0.rc1.5mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6-2.6.8.1-24mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-stripped-2.6-2.6.8.1-24mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.22.41mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.22.41mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-i686-up-4GB-2.4.22.41mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-p3-smp-64GB-2.4.22.41mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.22.41mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.22.41mdk-1-1mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.22-41mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK10.0")
 || rpm_exists(rpm:"kernel-", release:"MDK10.1")
 || rpm_exists(rpm:"kernel-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0814", value:TRUE);
 set_kb_item(name:"CVE-2004-0816", value:TRUE);
 set_kb_item(name:"CVE-2004-0883", value:TRUE);
 set_kb_item(name:"CVE-2004-0949", value:TRUE);
 set_kb_item(name:"CVE-2004-1016", value:TRUE);
 set_kb_item(name:"CVE-2004-1057", value:TRUE);
 set_kb_item(name:"CVE-2004-1058", value:TRUE);
 set_kb_item(name:"CVE-2004-1068", value:TRUE);
 set_kb_item(name:"CVE-2004-1069", value:TRUE);
 set_kb_item(name:"CVE-2004-1070", value:TRUE);
 set_kb_item(name:"CVE-2004-1071", value:TRUE);
 set_kb_item(name:"CVE-2004-1072", value:TRUE);
 set_kb_item(name:"CVE-2004-1073", value:TRUE);
 set_kb_item(name:"CVE-2004-1074", value:TRUE);
 set_kb_item(name:"CVE-2004-1137", value:TRUE);
 set_kb_item(name:"CVE-2004-1151", value:TRUE);
 set_kb_item(name:"CVE-2004-1235", value:TRUE);
 set_kb_item(name:"CVE-2005-0001", value:TRUE);
 set_kb_item(name:"CVE-2005-0003", value:TRUE);
}
exit(0, "Host is not affected");
