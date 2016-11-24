
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29774);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1104: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1104");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues and several bugs
  in the Red Hat Enterprise Linux 4 kernel are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  A flaw was found in the handling of IEEE 802.11 frames, which affected
  several wireless LAN modules. In certain situations, a remote attacker
  could trigger this flaw by sending a malicious packet over a wireless
  network, causing a denial of service (kernel crash).
  (CVE-2007-4997, Important)

  A memory leak was found in the Red Hat Content Accelerator kernel patch.
  A local user could use this flaw to cause a denial of service (memory
  exhaustion). (CVE-2007-5494, Important)

  Additionally, the following bugs were fixed:

  * when running the "ls -la" command on an NFSv4 mount point, incorrect
  file attributes, and outdated file size and timestamp information were
  returned. As well, symbolic links may have been displayed as actual files.

  * a bug which caused the cmirror write path to appear deadlocked after a
  successful recovery, which may have caused syncing to hang, has been
  resolved.

  * a kernel panic which occurred when manually configuring LCS interfaces on
  the IBM S/390 has been resolved.

  * when running a 32-bit binary on a 64-bit system, it was possible to
  mmap page at address 0 without flag MAP_FIXED set. This has been
  resolved in these updated packages.

  * the Non-Maskable Interrupt (NMI) Watchdog did not increment the NMI
  interrupt counter in "/proc/interrupts" on systems running an AMD Opteron
  CPU. This caused systems running NMI Watchdog to restart at regular
  intervals.

  * a bug which caused the diskdump utility to run very slowly on devices
  using Fusion MPT has been resolved.

  All users are advised to upgrade to these updated packages, which resolve
  these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1104.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4997", "CVE-2007-5494");
script_summary(english: "Check for the version of the kernel packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kernel-2.6.9-67.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-67.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-67.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-67.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-67.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-67.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-67.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-67.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-67.0.1.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
