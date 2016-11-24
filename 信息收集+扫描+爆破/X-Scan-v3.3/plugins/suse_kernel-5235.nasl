
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41532);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for Linux kernel (kernel-5235)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-5235");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

CVE-2008-2136: tunneled ipv6 packets (SIT) could trigger a
memory leak in the kernel. Remote attackers could exploit
that to crash machines.

Additionally the following bugfixes have been included for
all platforms:

- patches.xfs/xfs-kern_31033a_Fix-fsync-b0rkage.patch: Fix
  XFS fsync breakage (bnc#388798).

- patches.fixes/sit-add-missing-kfree_skb: sit - Add
  missing kfree_skb() on pskb_may_pull() failure.
  (bnc#389152)

-
patches.xfs/xfs-kern_30701a_Ensure-a-btree-insert-returns-a-
  valid-cursor.patch: Ensure a btree insert returns a valid
  cursor. ( bnc#388806).

- patches.fixes/369802_d_path_fix.patch: fix d_path for
  pseudo filesystems (bnc#369802).

- patches.fixes/ignore_lost_ticks: fixed do_vgettimeofday()
  and other issues with this patch (bnc#267050)

- patches.drivers/pci-express-aer-aerdriver-off.patch: PCI
  - add possibility to turn AER off (bnc#382033)

- patches.drivers/pci-express-aer-documentation: PCI - add
  AER documentation (bnc#382033)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-5235");
script_end_attributes();

script_cve_id("CVE-2008-2136");
script_summary(english: "Check for the kernel-5235 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.60-0.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.60-0.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.60-0.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.60-0.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.60-0.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.60-0.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.60-0.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-vmi-2.6.16.60-0.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-vmipae-2.6.16.60-0.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.60-0.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.60-0.23", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
