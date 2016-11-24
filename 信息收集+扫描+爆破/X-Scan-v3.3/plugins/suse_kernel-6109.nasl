
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41538);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Security update for Linux kernel (kernel-6109)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-6109");
 script_set_attribute(attribute: "description", value: "This Linux kernel update for SUSE Linux Enterprise 10
Service Pack 2 fixes various bugs and several security
issues.

Following security issues were fixed: CVE-2009-0675: The
skfp_ioctl function in drivers/net/skfp/skfddi.c in the
Linux kernel permits SKFP_CLR_STATS requests only when the
CAP_NET_ADMIN capability is absent, instead of when this
capability is present, which allows local users to reset
the driver statistics, related to an 'inverted logic' issue.

CVE-2009-0676: The sock_getsockopt function in
net/core/sock.c in the Linux kernel does not initialize a
certain structure member, which allows local users to
obtain potentially sensitive information from kernel memory
via an SO_BSDCOMPAT getsockopt request.

CVE-2009-0028: The clone system call in the Linux kernel
allows local users to send arbitrary signals to a parent
process from an unprivileged child process by launching an
additional child process with the CLONE_PARENT flag, and
then letting this new process exit.

CVE-2008-1294: The Linux kernel does not check when a user
attempts to set RLIMIT_CPU to 0 until after the change is
made, which allows local users to bypass intended resource
limits.

CVE-2009-0065: Buffer overflow in net/sctp/sm_statefuns.c
in the Stream Control Transmission Protocol (sctp)
implementation in the Linux kernel allows remote attackers
to have an unknown impact via an FWD-TSN (aka FORWARD-TSN)
chunk with a large stream ID.

CVE-2009-1046: The console selection feature in the Linux
kernel when the UTF-8 console is used, allows physically
proximate attackers to cause a denial of service (memory
corruption) by selecting a small number of 3-byte UTF-8
characters, which triggers an an off-by-two memory error.
It is is not clear if this can be exploited at all.

Also a huge number of regular bugs were fixed, please see
the RPM changelog for full details.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-6109");
script_end_attributes();

script_cve_id("CVE-2008-1294", "CVE-2009-0028", "CVE-2009-0065", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-1046");
script_summary(english: "Check for the kernel-6109 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.60-0.37_f594963d", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.60-0.37_f594963d", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.60-0.37_f594963d", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.60-0.37_f594963d", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.60-0.37_f594963d", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.60-0.37_f594963d", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.60-0.37_f594963d", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-vmi-2.6.16.60-0.37_f594963d", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-vmipae-2.6.16.60-0.37_f594963d", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.60-0.37_f594963d", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.60-0.37_f594963d", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
