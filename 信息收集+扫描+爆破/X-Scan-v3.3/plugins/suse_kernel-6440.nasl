
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42009);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Linux Kernel update (kernel-6440)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-6440");
 script_set_attribute(attribute: "description", value: "This kernel update for openSUSE 10.3 fixes some bugs and
several security problems.

The following security issues are fixed: CVE-2009-2692: A
missing NULL pointer check in the socket sendpage function
can be used by local attackers to gain root privileges.

CVE-2009-2406: A kernel stack overflow when mounting
eCryptfs filesystems in parse_tag_11_packet() was fixed.
Code execution might be possible of ecryptfs is in use.

CVE-2009-2407: A kernel heap overflow when mounting
eCryptfs filesystems in parse_tag_3_packet() was fixed.
Code execution might be possible of ecryptfs is in use.

The compiler option -fno-delete-null-pointer-checks was
added to the kernel build, and the -fwrapv compiler option
usage was fixed to be used everywhere. This works around
the compiler removing checks too aggressively.

CVE-2009-1389: A crash in the r8169 driver when receiving
large packets was fixed. This is probably exploitable only
in the local network.

CVE-2009-0676: A memory disclosure via the SO_BSDCOMPAT
socket option was fixed.

CVE-2009-1630: The nfs_permission function in fs/nfs/dir.c
in the NFS client implementation when atomic_open is
available, does not check execute (aka EXEC or MAY_EXEC)
permission bits, which allows local users to bypass
permissions and execute files, as demonstrated by files on
an NFSv4 fileserver.

random: make get_random_int() was made more random to
enhance ASLR protection.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-6440");
script_end_attributes();

script_cve_id("CVE-2009-2692", "CVE-2009-2406", "CVE-2009-2407", "CVE-2009-1389", "CVE-2009-0676", "CVE-2009-1630");
script_summary(english: "Check for the kernel-6440 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.22.19-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.22.19-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.22.19-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.22.19-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.22.19-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.22.19-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.22.19-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.22.19-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.22.19-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
