
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41533);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Security update for Linux kernel (kernel-5473)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-5473");
 script_set_attribute(attribute: "description", value: "This is a respin of the previous kernel update, which got
retracted due to an IDE-CDROM regression, where any IDE
CDROM access would hang or crash the system. Only this
problem was fixed additionally.

This kernel update fixes the following security problems:

CVE-2008-1615: On x86_64 a denial of service attack could
be used by local attackers to immediately panic / crash the
machine.

CVE-2008-1669: Fixed a SMP ordering problem in fcntl_setlk
could potentially allow local attackers to execute code by
timing file locking.

CVE-2008-2372: Fixed a resource starvation problem in the
handling of ZERO mmap pages.

CVE-2008-1673: The asn1 implementation in (a) the Linux
kernel, as used in the cifs and ip_nat_snmp_basic modules
does not properly validate length values during decoding of
ASN.1 BER data, which allows remote attackers to cause a
denial of service (crash) or execute arbitrary code via (1)
a length greater than the working buffer, which can lead to
an unspecified overflow; (2) an oid length of zero, which
can lead to an off-by-one error; or (3) an indefinite
length for a primitive encoding.

CVE-2008-2812: Various tty / serial devices did not check
functionpointers for NULL before calling them, leading to
potential crashes or code execution. The devices affected
are usually only accessible by the root user though.

CVE-2008-2931: A missing permission check in mount changing
was added which could have been used by local attackers to
change the mountdirectory.

Additionaly a very large number of bugs was fixed. Details
can be found in the RPM changelog of the included packages.

OCFS2 has been upgraded to the 1.4.1 release:
   - Endian fixes
   - Use slab caches for DLM objects
   - Export DLM state info to debugfs
   - Avoid ENOSPC in rare conditions when free inodes are
reserved by other nodes
   - Error handling fix in ocfs2_start_walk_page_trans()
   - Cleanup lockres printing
   - Allow merging of extents
   - Fix to allow changing permissions of symlinks
   - Merged local fixes upstream (no code change)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-5473");
script_end_attributes();

script_cve_id("CVE-2008-1615", "CVE-2008-1669", "CVE-2008-1673", "CVE-2008-2372", "CVE-2008-2812", "CVE-2008-2931");
script_summary(english: "Check for the kernel-5473 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.60-0.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.60-0.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.60-0.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.60-0.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.60-0.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.60-0.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.60-0.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-vmi-2.6.16.60-0.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-vmipae-2.6.16.60-0.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.60-0.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.60-0.27", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
