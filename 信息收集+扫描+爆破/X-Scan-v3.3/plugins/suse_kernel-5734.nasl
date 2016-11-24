
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35026);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for Linux Kernel (x86) (kernel-5734)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-5734");
 script_set_attribute(attribute: "description", value: "This patch updates the SUSE Linux Enterprise 10 SP1 kernel.
It fixes various bugs and security issues.

Following security issues are addressed:

CVE-2008-4210: fs/open.c in the Linux kernel before 2.6.22
does not properly strip setuid and setgid bits when there
is a write to a file, which allows local users to gain the
privileges of a different group, and obtain sensitive
information or possibly have unspecified other impact, by
creating an executable file in a setgid directory through
the (1) truncate or (2) ftruncate function in conjunction
with memory-mapped I/O.

CVE-2008-3528: The ext[234] filesystem code fails to
properly handle corrupted data structures. With a mounted
filesystem image or partition that have corrupted
dir->i_size and dir->i_blocks, a user performing either a
read or write operation on the mounted image or partition
can lead to a possible denial of service by spamming the
logfile.

CVE-2007-6716: fs/direct-io.c in the dio subsystem in the
Linux kernel did not properly zero out the dio struct,
which allows local users to cause a denial of service
(OOPS), as demonstrated by a certain fio test.

All other bugfixes can be found by looking at the RPM
changelog.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-5734");
script_end_attributes();

script_cve_id("CVE-2007-6716", "CVE-2008-3528", "CVE-2008-4210");
script_summary(english: "Check for the kernel-5734 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.54-0.2.12", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.54-0.2.12", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.54-0.2.12", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.54-0.2.12", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.54-0.2.12", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.54-0.2.12", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.54-0.2.12", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.54-0.2.12", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.54-0.2.12", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.16.54-0.2.12", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.54-0.2.12", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.54-0.2.12", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.54-0.2.12", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.54-0.2.12", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.54-0.2.12", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.54-0.2.12", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
