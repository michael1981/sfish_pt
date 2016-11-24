
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41942);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1455: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1455");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix one security issue and several bugs are
  now available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security fix:

  * a NULL pointer dereference flaw was found in the Multiple Devices (md)
  driver in the Linux kernel. If the "suspend_lo" or "suspend_hi" file on the
  sysfs file system ("/sys/") is modified when the disk array is inactive, it
  could lead to a local denial of service or privilege escalation. Note: By
  default, only the root user can write to the files mentioned above.
  (CVE-2009-2849, Moderate)

  Bug fixes:

  * a bug in nlm_lookup_host() could lead to un-reclaimed locks on file
  systems, resulting in umount failing and NFS service relocation issues for
  clusters. (BZ#517967)

  * a bug in the sky2 driver prevented the phy from being reset properly on
  some hardware when it hanged, preventing a link from coming back up.
  (BZ#517976)

  * disabling MSI-X for qla2xxx also disabled MSI interrupts. (BZ#519782)

  * performance issues with reads when using the qlge driver on PowerPC
  systems. A system hang could also occur during reboot. (BZ#519783)

  * unreliable time keeping for Red Hat Enterprise Linux virtual machines.
  The KVM pvclock code is now used to detect/correct lost ticks. (BZ#520685)

  * /proc/cpuinfo was missing flags for new features in supported processors,
  possibly preventing the operating system and applications from getting the
  best performance. (BZ#520686)

  * reading/writing with a serial loopback device on a certain IBM system did
  not work unless booted with "pnpacpi=off". (BZ#520905)

  * mlx4_core failed to load on systems with more than 32 CPUs. (BZ#520906)

  * on big-endian platforms, interfaces using the mlx4_en driver and Large
  Receive Offload (LRO) did not handle VLAN traffic properly (a segmentation
  fault in the VLAN stack in the kernel occurred). (BZ#520908)

  * due to a lock being held for a long time, some systems may have
  experienced "BUG: soft lockup" messages under very heavy load. (BZ#520919)

  * incorrect APIC timer calibration may have caused a system hang during
  boot, as well as the system time becoming faster or slower. A warning is
  now provided. (BZ#521238)

  * a Fibre Channel device re-scan via \'echo "---" > /sys/class/scsi_host/
  host[x]/scan\' may not complete after hot adding a drive, leading to soft
  lockups ("BUG: soft lockup detected"). (BZ#521239)

  * the Broadcom BCM5761 network device was unable to be initialized
  properly; therefore, the associated interface could not obtain an IP
  address via DHCP, or be assigned one manually. (BZ#521241)

  * when a process attempted to read from a page that had first been
  accessed by writing to part of it (via write(2)), the NFS client needed to
  flush the modified portion of the page out to the server, and then read
  the entire page back in. This flush caused performance issues. (BZ#521244)

  * a kernel panic when using bnx2x devices and LRO in a bridge. A warning is
  now provided to disable LRO in these situations. (BZ#522636)

  * the scsi_dh_rdac driver was updated to recognize the Sun StorageTek
  Flexline 380. (BZ#523237)

  * in FIPS mode, random number generators are required to not return the
  first block of random data they generate, but rather save it to seed the
  repetition check. This update brings the random number generator into
  conformance. (BZ#523289)

  * an option to disable/enable the use of the first random block is now
  provided to bring ansi_cprng into compliance with FIPS-140 continuous test
  requirements. (BZ#523290)

  * running the SAP Linux Certification Suite in a KVM guest caused severe
  SAP kernel errors, causing it to exit. (BZ#524150)

  * attempting to \'online\' a CPU for a KVM guest via sysfs caused a system
  crash. (BZ#524151)

  * when using KVM, pvclock returned bogus wallclock values. (BZ#524152)

  * the clock could go backwards when using the vsyscall infrastructure.
  (BZ#524527)

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The system must be rebooted for this
  update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1455.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2849");
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

if ( rpm_check( reference:"kernel-2.6.18-164.2.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-164.2.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-164.2.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-164.2.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-164.2.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-164.2.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-164.2.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-164.2.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-164.2.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-164.2.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.18-164.2.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-164.2.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-164.2.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-164.2.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-164.2.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-164.2.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-164.2.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-164.2.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-164.2.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-164.2.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
