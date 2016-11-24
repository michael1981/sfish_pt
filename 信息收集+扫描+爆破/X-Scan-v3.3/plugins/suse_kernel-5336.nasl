
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33252);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Linux Kernel security update. (kernel-5336)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-5336");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

CVE-2008-1615: On x86_64 a denial of service attack could
be used by local attackers to immediately panic / crash the
machine.

CVE-2008-2358: A security problem in DCCP was fixed, which
could be used by remote attackers to crash the machine.

CVE-2007-6206: An information leakage during coredumping of
root processes was fixed.

CVE-2007-6712: A integer overflow in the hrtimer_forward
function (hrtimer.c) in Linux kernel, when running on
64-bit systems, allows local users to cause a denial of
service (infinite loop) via a timer with a large expiry
value, which causes the timer to always be expired.

CVE-2008-2136: A problem in SIT IPv6 tunnel handling could
be used by remote attackers to immediately crash the
machine.

CVE-2008-1669: Fixed a SMP ordering problem in fcntl_setlk
could potentially allow local attackers to execute code by
timing file locking.

CVE-2008-1367: Clear the 'direction' flag before calling
signal handlers. For specific not yet identified programs
under specific timing conditions this could potentially
have caused memory corruption or code execution.

CVE-2008-1375: Fixed a dnotify race condition, which could
be used by local attackers to potentially execute code.

CVE-2007-6282: A remote attacker could crash the IPSec/IPv6
stack by sending a bad ESP packet. This requires the host
to be able to receive such packets (default filtered by the
firewall).

CVE-2007-5500: A ptrace bug could be used by local
attackers to hang their own processes indefinitely.

CVE-2007-5904: A remote buffer overflow in CIFS was fixed
which could be used by remote attackers to crash the
machine or potentially execute code.

And the following bugs (numbers are
https://bugzilla.novell.com/ references):
- patches.arch/x86-nosmp-implies-noapic.patch: When booting
  with nosmp or maxcpus=0 on i386 or x86-64, we must
  disable the I/O APIC, otherwise the system won't boot in
  most cases (bnc#308540).
- patches.arch/i386-at-sysinfo-ehdr: i386: make
  AT_SYSINFO_EHDR consistent with AT_SYSINFO (bnc#289641).
- patches.suse/bonding-workqueue: Update to fix a hang when
  closing a bonding device (342994).
- patches.fixes/mptspi-dv-renegotiate-oops: mptlinux
  crashes on kernel 2.6.22 (bnc#271749).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-5336");
script_end_attributes();

script_cve_id("CVE-2008-1615", "CVE-2008-2358", "CVE-2007-6206", "CVE-2007-6712", "CVE-2008-2136", "CVE-2008-1669", "CVE-2008-1367", "CVE-2008-1375", "CVE-2007-6282", "CVE-2007-5500", "CVE-2007-5904");
script_summary(english: "Check for the kernel-5336 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.18.8-0.10", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.18.8-0.10", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-iseries64-2.6.18.8-0.10", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.18.8-0.10", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.18.8-0.10", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.18.8-0.10", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.18.8-0.10", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18.8-0.10", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.18.8-0.10", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
