
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
 script_id(33253);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Linux Kernel update (kernel-5339)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kernel-5339");
 script_set_attribute(attribute: "description", value: "This kernel update fixes the following security problems:
CVE-2008-2136: A problem in SIT IPv6 tunnel handling could
be used by remote attackers to immediately crash the
machine.

CVE-2008-1615: On x86_64 a denial of service attack could
be used by local attackers to immediately panic / crash the
machine.

CVE-2008-2148: The permission checking in sys_utimensat was
incorrect and local attackers could change the filetimes of
files they do not own to the current time.

CVE-2008-1669: Fixed a SMP ordering problem in fcntl_setlk
could potentially allow local attackers to execute code by
timing file locking.

CVE-2008-1375: Fixed a dnotify race condition, which could
be used by local attackers to potentially execute code.

CVE-2007-6282: A remote attacker could crash the IPSec/IPv6
stack by sending a bad ESP packet. This requires the host
to be able to receive such packets (default filtered by the
firewall).

CVE-2008-1367: Clear the 'direction' flag before calling
signal handlers. For specific not yet identified programs
under specific timing conditions this could potentially
have caused memory corruption or code execution.

And the following bugs (numbers are
https://bugzilla.novell.com/ references):
- patches.fixes/input-add-amilo-pro-v-to-nomux.patch:
  Update the patch to include also 2030 model to nomux list
  (bnc#389169).
- patches.apparmor/fix-net.diff: AppArmor: fix Oops in
  apparmor_socket_getpeersec_dgram() (bnc#378608).
- patches.fixes/input-alps-update.patch: Input: fix the
  AlpsPS2 driver (bnc#357881).
-
patches.arch/cpufreq_fix_acpi_driver_on_BIOS_changes.patch:
  CPUFREQ: Check against freq changes from the BIOS
  (334378).
-
patches.fixes/ieee1394-limit-early-node-speed-to-host-interf
  ace-speed: ieee1394: limit early node speed to host
  interface speed (381304).
- patches.fixes/forcedeth_realtec_phy_fix: Fix a regression
  to the GA kernel for some forcedeth cards  (bnc#379478)
- pci-revert-SMBus-unhide-on-nx6110.patch: Do not unhide
  the SMBus on the HP Compaq nx6110, it's unsafe.
- patches.drivers/e1000-disable-l1aspm.patch: Disable L1
  ASPM power savings for 82573 mobile variants, it's broken
  (bnc#254713, LTC34077).
- patches.drivers/libata-improve-hpa-error-handling:
  libata: improve HPA error handling (365534).
- rpm/kernel-binary.spec.in: Added Conflicts:
  libc.so.6()(64bit) to i386 arch (364433).
-
patches.drivers/libata-disallow-sysfs-read-access-to-force-p
  aram: libata: don't allow sysfs read access to force
  param (362599).
- patches.suse/bonding-workqueue: Update to fix a hang when
  closing a bonding device (342994).
- patches.fixes/mptspi-dv-renegotiate-oops: mptlinux
  crashes on kernel 2.6.22 (bnc#271749).
-
patches.drivers/usb-update-sierra-and-option-device-ids-from
  -2.6.25-rc3.patch: USB: update sierra and option device
  ids from 2.6.25-rc3 (343167).
- patches.arch/x86-nvidia-timer-quirk: Disable again
  (#302327)  The PCI ID lists are not complete enough and
  let's have the same crap as mainline for this for now.
- patches.fixes/input-add-lenovo-3000-n100-to-nomux.patch:
  Input: add Lenovo 3000 N100 to nomux blacklist
  (bnc#284013).
- patches.suse/bonding-bh-locking: Add missing chunks. The
  SLES10 SP1 version of the patch was updated in May 2007
  but the openSuse 10.3 version was forgotten (260069).
-
patches.fixes/knfsd-Allow-NFSv2-3-WRITE-calls-to-succeed-whe
  n-krb.patch: knfsd: Allow NFSv2/3 WRITE calls to succeed
  when krb5i etc is used. (348737).
-
patches.fixes/md-fix-an-occasional-deadlock-in-raid5.patch:
  md: fix an occasional deadlock in raid5 (357088).
- patches.drivers/libata-quirk_amd_ide_mode: PCI: modify
  SATA IDE mode quirk (345124).
- Fix section mismatch build failure w/ gcc 4.1.2.  bug
  #361086.
- patches.drivers/libata-implement-force-parameter: libata:
  implement libata.force module parameter (337610).

Lots of XEN Fixes (not detailed listed). Lots of RT Fixes
(not detailed listed).

- Update to 2.6.22.18
  - removes upstreamed patch:
    - patches.fixes/vmsplice-pipe-exploit (CVE-2008-0600)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch kernel-5339");
script_end_attributes();

script_cve_id("CVE-2008-2136", "CVE-2008-1615", "CVE-2008-2148", "CVE-2008-1669", "CVE-2008-1375", "CVE-2007-6282", "CVE-2008-1367", "CVE-2008-0600");
script_summary(english: "Check for the kernel-5339 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kernel-bigsmp-2.6.22.18-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.22.18-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-default-2.6.22.18-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-kdump-2.6.22.18-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-ppc64-2.6.22.18-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-source-2.6.22.18-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-syms-2.6.22.18-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.22.18-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kernel-xenpae-2.6.22.18-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
