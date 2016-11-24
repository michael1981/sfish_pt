
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
 script_id(29487);
 script_version ("$Revision: 1.9 $");
 script_name(english: "SuSE Security Update:  Security update for Linux kernel (kernel-4185)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-4185");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:

- CVE-2007-2242: The IPv6 protocol allows remote attackers
  to cause a denial of service via crafted IPv6 type 0
  route headers (IPV6_RTHDR_TYPE_0) that create network
  amplification between two routers. 

  The default is that RH0 is disabled now. To adjust this,
write to the file /proc/net/accept_source_route6.

- CVE-2007-2453: The random number feature in the Linux
  kernel 2.6 (1) did not properly seed pools when there is
  no entropy, or (2) used an incorrect cast when extracting
  entropy, which might have caused the random number
  generator to provide the same values after reboots on
  systems without an entropy source.

- CVE-2007-2876: A NULL pointer dereference in SCTP
  connection tracking could be caused by a remote attacker
  by sending specially crafted packets. Note that this
  requires SCTP set-up and active to be exploitable.

- CVE-2007-3105: Stack-based buffer overflow in the random
  number generator (RNG) implementation in the Linux kernel
  before 2.6.22 might allow local root users to cause a
  denial of service or gain privileges by setting the
  default wakeup threshold to a value greater than the
  output pool size, which triggers writing random numbers
  to the stack by the pool transfer function involving
  'bound check ordering'.

 Since this value can only be changed by a root user,
exploitability is low.

- CVE-2007-3107: The signal handling in the Linux kernel,
  when run on PowerPC systems using HTX, allows local users
  to cause a denial of service via unspecified vectors
  involving floating point corruption and concurrency.

- CVE-2007-2525: Memory leak in the PPP over Ethernet
  (PPPoE) socket implementation in the Linux kernel allowed
  local users to cause a denial of service (memory
  consumption) by creating a socket using connect, and
  releasing it before the PPPIOCGCHAN ioctl is initialized.

- CVE-2007-3513: The lcd_write function in
  drivers/usb/misc/usblcd.c in the Linux kernel did not
  limit the amount of memory used by a caller, which
  allowed local users to cause a denial of service (memory
  consumption).

- CVE-2007-3848: A local attacker could send a death signal
  to a setuid root program under certain conditions,
  potentially causing unwanted behaviour in this program.

- CVE-2007-3851: On machines with a Intel i965 based
  graphics card local users with access to the direct
  rendering devicenode could overwrite memory on the
  machine and so gain root privileges.

- Fixed a denial of service possibility where a local
  attacker with access to a pwc camera device could hang
  the USB subsystem. [#302194]

and the following non security bugs:

- patches.arch/ppc-oprofile-970mp.patch: enable ppc64/970
  MP,  requires oprofile 0.9.3 [#252696]
- patches.arch/x86_64-no-tsc-with-C3: don't use TSC on
  x86_64 Intel systems when CPU has C3 [#254061]
- patches.arch/x86_64-hpet-lost-interrupts-fix.patch:
  backport x86_64 hpet lost interrupts code [#257035]
- patches.fixes/fusion-nat-consumption-fix: handle a
  potential race in mptbase. This fixes a NaT consumption
  crash [#257412]
- patches.arch/ia64-skip-clock-calibration: enabled
  [#259501]
- patches.fixes/md-raid1-handle-read-error: Correctly
  handle  read errors from a failed drive in raid1 [#261459]
- patches.arch/ia64-fix-kdump-on-init: kdump on INIT needs
  multi-nodes sync-up (v.2) [#265764]
- patches.arch/ia64-perfmon-fix-2: race condition between
  pfm_context_create and pfm_read [#268131]
- patches.fixes/cpufreq_ppc_boot_option.patch: workaround
  for _PPC (BIOS cpufreq limitations) [#269579]
- patches.arch/acpi_package_object_support.patch: ACPI
  package object as method parameter support (in AML)
  [#270956]
- patches.fixes/ia64_cpufreq_PDC.patch: correctly assign as
  cpufreq capable driver (_PDC) to BIOS [#270973]
- patches.arch/ia64-kdump-hpzx1-ioc-workaround: update to
  latest upstream version of the patch [#271158]
- patches.suse/delayacct_memleak.patch: Fix delayacct
  memory leak [#271187]
- patches.fixes/fc_transport-check-portstate-before-scan:
  check FC portstates before invoking target scan [#271338]
- patches.fixes/unusual14cd.patch: quirk for 14cd:6600
  [#274087]
-
patches.fixes/reiserfs-change_generation_on_update_sd.diff:
  fix assertion failure in reiserfs [#274288]
-
patches.drivers/d-link-dge-530t-should-use-the-skge-driver.p
  atch: D-Link DGE-530T should use the skge driver [#275376]
- patches.arch/ia64-dont-unwind-running-tasks.patch: Only
  unwind  non-running tasks [#275854]
- patches.fixes/dm-mpath-rdac-avt-support: short circuit
  RDAC hardware handler in AVT mode [#277834]
- patches.fixes/lkcd-re-enable-valid_phys_addr_range:
  re-enable the valid_phys_addr_range() check [#279433]
- patches.drivers/cciss-panic-on-reboot: when root
  filesystem is xfs the server cannot do a second reboot
  [#279436] Also resolves same issue in [#291759].
- patches.drivers/ide-hpt366-fix-302n-oops:  fix hpt302n
  oops [#279705]
- patches.fixes/serial-8250-backup-timer-2-deadlock-fix:
  fix possible deadlock [#280771]
- patches.fixes/nfs-osync-error-return: ensure proper error
  return from O_SYNC writes [#280833]
- patches.fixes/acpi_pci_hotplug_poweroff.patch: ACPI PCI
  hotplug driver acpiphp unable to power off PCI slot
  [#281234]
-
patches.drivers/pci-hotplug-acpiphp-remove-hot-plug-paramete
  r-write-to-pci-host-bridge.patch: remove hot plug
  parameter write to PCI host bridge [#281239] 
- patches.fixes/scsi-set-correct-resid: Incorrect 'resid'
  field values when using a tape device [#281640]
- patches.drivers/usb-edgeport-epic-support.patch: USB: add
  EPIC support to the io_edgeport driver [#281921]
- patches.fixes/usb-hid-ncr-no-init-reports.patch: HID:
  Don't initialize reports for NCR devices [#281921]
- patches.drivers/ppc-power6-ehea.patch: use decimal
  values  in sysfs propery logical_port_id, fix panic when
  adding / removing logical eHEA ports [#283070]
- patches.arch/ppc-power6-ebus.patch: DLPAR Adapter
  add/remove  functionality for eHEA [#283239]
- patches.fixes/nfs-enospc: Return ENOSPC and EDQUOT to NFS
  write requests more promptly [#284042]
-
patches.drivers/pci-hotplug-acpiphp-avoid-acpiphp-cannot-get
  -bridge-info-pci-hotplug-failure.patch: PCI: hotplug:
  acpiphp: avoid acpiphp 'cannot get bridge info' PCI
  hotplug failure [#286193]
- patches.drivers/lpfc-8.1.10.9-update: lpfc update to
  8.1.10.9 [#286223]
- patches.fixes/make-swappiness-safer-to-use.patch: Handle
  low swappiness gracefully [#288799]
- patches.arch/ppc-oprofile-power5plusplus.patch: oprofile
  support for Power 5++ [#289223]
- patches.drivers/ppc-power6-ehea.patch: Fixed possible
  kernel  panic on VLAN packet recv [#289301]
- patches.fixes/igrab_should_check_for_i_clear.patch:
  igrab() should check for I_CLEAR [#289576]
- patches.fixes/wait_for_sysfs_population.diff: Driver
  core: bus device event delay [#289964]
-
patches.drivers/scsi-throttle-SG_DXFER_TO_FROM_DEV-warning-b
  etter: better throttling of SG_DXFER_TO_FROM_DEV warning
  messages  [#290117]
-
patches.arch/mark-unwind-info-for-signal-trampolines-in-vdso
  s.patch: Mark unwind info for signal trampolines in vDSOs
  [#291421]
- patches.fixes/hugetlbfs-stack-grows-fix.patch: don't
  allow the  stack to grow into hugetlb reserved regions
  [#294021]
- patches.drivers/alsa-post-sp1-hda-analog-update: add
  support of of missing AD codecs [#294471]
- patches.drivers/alsa-post-sp1-hda-conexant-fixes: fix
  unterminated arrays [#294480]
- patches.fixes/fix_hpet_init_race.patch: fix a race in
  HPET initialization on x86_64 resulting in a lockup on
  boot [#295115]
- patches.drivers/alsa-post-sp1-hda-sigmatel-pin-fix: Fix
  number of pin widgets with STAC codecs [#295653]
-
patches.fixes/pci-pcieport-driver-remove-invalid-warning-mes
  sage.patch: PCI: pcieport-driver: remove invalid warning
  message [#297135] [#298561]
- patches.kernel.org/patch-2.6.16.NN-$((NN+1)), NN =
  18,...,52: update to Kernel 2.6.16.53; lots of bugfixes
  [#298719] [#186582] [#186583] [#186584]
- patches.fixes/ocfs2-1.2-svn-r3027.diff: proactive patch
  [#298845]
- patches.drivers/b44-phy-fix: Fix frequent PHY resets
  under load on b44  [#301653]
- dd patches.arch/ppc-eeh-node-status-okay.patch firmware
  returns 'okay' instead of 'ok' for node status [#301788]
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-4185");
script_end_attributes();

script_cve_id("CVE-2007-2242", "CVE-2007-2453", "CVE-2007-2525", "CVE-2007-2876", "CVE-2007-3105", "CVE-2007-3107", "CVE-2007-3513", "CVE-2007-3848", "CVE-2007-3851");
script_summary(english: "Check for the kernel-4185 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"kernel-bigsmp-2.6.16.53-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.16.53-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.53-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.16.53-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.53-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.53-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.53-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.53-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.53-0.8", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-bigsmp-2.6.16.53-0.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.16.53-0.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.16.53-0.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.16.53-0.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.16.53-0.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.16.53-0.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.16.53-0.8", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
