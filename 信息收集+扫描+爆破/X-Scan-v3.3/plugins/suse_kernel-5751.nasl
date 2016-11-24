
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(34755);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Linux Kernel security update. (kernel-5751)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-5751");
 script_set_attribute(attribute: "description", value: "This kernel update fixes various bugs and also several
security issues:

CVE-2008-4576: Fixed a crash in SCTP INIT-ACK, on mismatch
between SCTP AUTH availability. This might be exploited
remotely for a denial of service (crash) attack.

CVE-2008-3833: The generic_file_splice_write function in
fs/splice.c in the Linux kernel does not properly strip
setuid and setgid bits when there is a write to a file,
which allows local users to gain the privileges of a
different group, and obtain sensitive information or
possibly have unspecified other impact, by splicing into an
inode in order to create an executable file in a setgid
directory.

CVE-2008-4210: fs/open.c in the Linux kernel before 2.6.22
does not properly strip setuid and setgid bits when there
is a write to a file, which allows local users to gain the
privileges of a different group, and obtain sensitive
information or possibly have unspecified other impact, by
creating an executable file in a setgid directory through
the (1) truncate or (2) ftruncate function in conjunction
with memory-mapped I/O.

CVE-2008-4302: fs/splice.c in the splice subsystem in the
Linux kernel before 2.6.22.2 does not properly handle a
failure of the add_to_page_cache_lru function, and
subsequently attempts to unlock a page that was not locked,
which allows local users to cause a denial of service
(kernel BUG and system crash), as demonstrated by the fio
I/O tool.

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

CVE-2008-3525: Added missing capability checks in
sbni_ioctl().

CVE-2008-3272: Fixed range checking in the snd_seq OSS
ioctl, which could be used to leak information from the
kernel.

CVE-2008-2931: The do_change_type function in
fs/namespace.c did not verify that the caller has the
CAP_SYS_ADMIN capability, which allows local users to gain
privileges or cause a denial of service by modifying the
properties of a mountpoint.

CVE-2008-2812: Various NULL ptr checks have been added to
tty op functions, which might have been used by local
attackers to execute code. We think that this affects only
devices openable by root, so the impact is limited.

CVE-2008-1673: Added range checking in ASN.1 handling for
the CIFS and SNMP NAT netfilter modules.

CVE-2008-3527: arch/i386/kernel/sysenter.c in the Virtual
Dynamic Shared Objects (vDSO) implementation in the Linux
kernel before 2.6.21 did not properly check boundaries,
which allows local users to gain privileges or cause a
denial of service via unspecified vectors, related to the
install_special_mapping, syscall, and syscall32_nopage
functions.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-5751");
script_end_attributes();

script_cve_id("CVE-2008-4576", "CVE-2008-3833", "CVE-2008-4210", "CVE-2008-4302", "CVE-2008-3528", "CVE-2007-6716", "CVE-2008-3525", "CVE-2008-3272", "CVE-2008-2931", "CVE-2008-2812", "CVE-2008-1673", "CVE-2008-3527");
script_summary(english: "Check for the kernel-5751 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.18.8-0.13", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.18.8-0.13", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-iseries64-2.6.18.8-0.13", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.18.8-0.13", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.18.8-0.13", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.18.8-0.13", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.18.8-0.13", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18.8-0.13", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.18.8-0.13", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
