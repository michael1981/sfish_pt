
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33432);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for Linux kernel (kernel-5375)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-5375");
 script_set_attribute(attribute: "description", value: "This kernel update fixes quite a number of security
problems:

CVE-2007-6282: A remote attacker could crash the IPSec/IPv6
stack by sending a bad ESP packet. This requires the host
to be able to receive such packets (default filtered by the
firewall).

CVE-2008-2136: A problem in SIT IPv6 tunnel handling could
be used by remote attackers to immediately crash the
machine.

CVE-2008-1615: On x86_64 a denial of service attack could
be used by local attackers to immediately panic / crash the
machine.

CVE-2007-6206: An information leakage during coredumping of
root processes was fixed.

CVE-2008-1669: Fixed a SMP ordering problem in fcntl_setlk
could potentially allow local attackers to execute code by
timing file locking.

CVE-2008-1375: Fixed a dnotify race condition, which could
be used by local attackers to potentially execute code.

CVE-2007-5500: A ptrace bug could be used by local
attackers to hang their own processes indefinitely.

CVE-2008-1367: Clear the 'direction' flag before calling
signal handlers. For specific not yet identified programs
under specific timing conditions this could potentially
have caused memory corruption or code execution.

CVE-2007-6151: The isdn_ioctl function in isdn_common.c
allowed local users to cause a denial of service via a
crafted ioctl struct in which ioctls is not null
terminated, which triggers a buffer overflow.


Non security related changes:

	OCFS2 was updated to version v1.2.9-1-r3100.

	Also a huge number of bugs were fixed. Please refer to the
RPM changelog for a detailed list.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-5375");
script_end_attributes();

script_cve_id("CVE-2007-5500", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6282", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1615", "CVE-2008-1669", "CVE-2008-2136");
script_summary(english: "Check for the kernel-5375 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.54-0.2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.54-0.2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.54-0.2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.54-0.2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.54-0.2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.54-0.2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.54-0.2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.54-0.2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.54-0.2.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.16.54-0.2.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.54-0.2.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.54-0.2.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.54-0.2.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.54-0.2.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.54-0.2.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.54-0.2.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
