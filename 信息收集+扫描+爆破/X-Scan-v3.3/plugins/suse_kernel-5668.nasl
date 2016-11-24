
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41535);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Security update for Linux kernel (kernel-5668)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-5668");
 script_set_attribute(attribute: "description", value: "This kernel update for SUSE Linux Enterprise 10 Service
Pack 2 fixes various bugs and some security problems:

CVE-2008-4210: When creating a file, open()/creat() allowed
the setgid bit to be set via the mode argument even when,
due to the bsdgroups mount option or the file being created
in a setgid directory, the new file's group is one which
the user is not a member of.  The local attacker could then
use ftruncate() and memory-mapped I/O to turn the new file
into an arbitrary binary and thus gain the privileges of
this group, since these operations do not clear the setgid
bit.'

CVE-2008-3528: The ext[234] filesystem code fails to
properly handle corrupted data structures. With a mounted
filesystem image or partition that have corrupted
dir->i_size and dir->i_blocks, a user performing either a
read or write operation on the mounted image or partition
can lead to a possible denial of service by spamming the
logfile.

CVE-2008-1514: The S/390 ptrace code allowed local users to
cause a denial of service (kernel panic) via the
user-area-padding test from the ptrace testsuite in 31-bit
mode, which triggers an invalid dereference.

CVE-2007-6716: fs/direct-io.c in the dio subsystem in the
Linux kernel did not properly zero out the dio struct,
which allows local users to cause a denial of service
(OOPS), as demonstrated by a certain fio test.

CVE-2008-3525: Added missing capability checks in
sbni_ioctl().


Also OCFS2 was updated to version v1.4.1-1.

The full amount of changes can be reviewed in the RPM
changelog.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-5668");
script_end_attributes();

script_cve_id("CVE-2007-6716", "CVE-2008-1514", "CVE-2008-3525", "CVE-2008-3528", "CVE-2008-4210");
script_summary(english: "Check for the kernel-5668 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.60-0.31", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.60-0.31", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.60-0.31", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.60-0.31", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.60-0.31", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.60-0.31", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.60-0.31", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-vmi-2.6.16.60-0.31", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-vmipae-2.6.16.60-0.31", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.60-0.31", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.60-0.31", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
