
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27299);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Linux Kernel update (kernel-4503)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-4503");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

- CVE-2007-4571: An information disclosure vulnerability in
  the ALSA driver can be exploited by local users to read
  sensitive data from the kernel memory.

- CVE-2007-4573: It was possible for local user to become
  root by exploitable a bug in the IA32 system call
  emulation. This affects x86_64 platforms with kernel
  2.4.x and 2.6.x before 2.6.22.7 only.

and the following non security bugs:

- supported.conf: Mark 8250 and 8250_pci as supported (only
  Xen kernels build them as modules)  [#260686]
- patches.fixes/bridge-module-get-put.patch: Module use
  count must be updated as bridges are created/destroyed
  [#267651]
- patches.fixes/nfsv4-MAXNAME-fix.diff: knfsd: query
  filesystem for NFSv4 getattr of FATTR4_MAXNAME  [#271803]
- patches.fixes/sky2-tx-sum-resume.patch: sky2: fix
  transmit state on resume  [#297132] [#326376]
- patches.suse/reiserfs-add-reiserfs_error.diff:
  patches.suse/reiserfs-use-reiserfs_error.diff:
  patches.suse/reiserfs-buffer-info-for-balance.diff: Fix
  reiserfs_error() with NULL superblock calls  [#299604]
- patches.fixes/acpi_disable_C_states_in_suspend.patch:
  ACPI: disable lower idle C-states across suspend/resume
  [#302482]
- kernel-syms.rpm: move the copies of the Modules.alias
  files from /lib/modules/... to /usr/src/linux-obj/... to
  avoid a file conflict between kernel-syms and other
  kernel-$flavor packages. The Modules.alias files in
  kernel-syms.rpm are intended for future use - [#307291]
- patches.fixes/jffs2-fix-ACL-vs-mode-handling: Fix ACL vs.
  mode handling.   [#310520]
-
patches.drivers/libata-sata_sil24-fix-IRQ-clearing-race-on-I
  RQ_WOC: sata_sil24: fix IRQ clearing race when
  PCIX_IRQ_WOC is used  [#327536]
- Update config files: Enabled CONFIG_DVB_PLUTO2 for i386
  since it's enabled everywhere else.  [#327790]
-
patches.drivers/libata-pata_ali-fix-garbage-PCI-rev-value: p
  ata_ali: fix garbage PCI rev value in ali_init_chipset()
  [#328422]
- patches.apparmor/apparmor-lsm-fix.diff:
  apparmor_file_mmap function parameters mismatch  [#328423]
- patches.drivers/libata-HPA-off-by-one-horkage: Fix HPA
  handling regression  [#329584]
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-4503");
script_end_attributes();

script_cve_id("CVE-2007-4571", "CVE-2007-4573");
script_summary(english: "Check for the kernel-4503 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.22.9-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.22.9-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.22.9-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.22.9-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.22.9-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.22.9-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.22.9-0.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
