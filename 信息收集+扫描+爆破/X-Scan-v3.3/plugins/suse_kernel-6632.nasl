
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42465);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for Linux kernel (kernel-6632)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-6632");
 script_set_attribute(attribute: "description", value: "This update fixes a several security issues and various
bugs in the SUSE Linux Enterprise 10 SP 2 kernel.

Following security issues were fixed: CVE-2009-3547: A race
condition during pipe open could be used by local attackers
to elevate privileges.

CVE-2009-2910: On x86_64 systems a information leak of high
register contents (upper 32bit) was fixed.

CVE-2009-3238: The randomness of the ASLR methods used in
the kernel was increased.

CVE-2009-1192: A information leak from the kernel due to
uninitialized memory in AGP handling was fixed.

CVE-2009-2909: A signed comparison in the ax25 sockopt
handler was fixed which could be used to crash the kernel
or potentially execute code.

CVE-2009-2848: The execve function in the Linux kernel did
not properly clear the current->clear_child_tid pointer,
which allows local users to cause a denial of service
(memory corruption) or possibly gain privileges via a clone
system call with CLONE_CHILD_SETTID or CLONE_CHILD_CLEARTID
enabled, which is not properly handled during thread
creation and exit.

CVE-2009-3002: Fixed various sockethandler getname leaks,
which could disclose memory previously used by the kernel
or other userland processes to the local attacker.

CVE-2009-1633: Multiple buffer overflows in the cifs
subsystem in the Linux kernel allow remote CIFS servers to
cause a denial of service (memory corruption) and possibly
have unspecified other impact via (1) a malformed Unicode
string, related to Unicode string area alignment in
fs/cifs/sess.c; or (2) long Unicode characters, related to
fs/cifs/cifssmb.c and the cifs_readdir function in
fs/cifs/readdir.c.

Also see the RPM changelog for more changes.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-6632");
script_end_attributes();

script_cve_id("CVE-2009-1192", "CVE-2009-1633", "CVE-2009-2848", "CVE-2009-2909", "CVE-2009-2910", "CVE-2009-3002", "CVE-2009-3238", "CVE-2009-3547");
script_summary(english: "Check for the kernel-6632 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.60-0.42.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.60-0.42.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.60-0.42.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.60-0.42.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.60-0.42.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.60-0.42.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.60-0.42.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-vmi-2.6.16.60-0.42.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-vmipae-2.6.16.60-0.42.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.60-0.42.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.60-0.42.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
