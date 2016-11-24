
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40609);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1211: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1211");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and several bugs
  are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  * Michael Tokarev reported a flaw in the Realtek r8169 Ethernet driver in
  the Linux kernel. This driver allowed interfaces using this driver to
  receive frames larger than what could be handled. This could lead to a
  remote denial of service or code execution. (CVE-2009-1389, Important)

  * a buffer overflow flaw was found in the CIFSTCon() function of the Linux
  kernel Common Internet File System (CIFS) implementation. When mounting a
  CIFS share, a malicious server could send an overly-long string to the
  client, possibly leading to a denial of service or privilege escalation on
  the client mounting the CIFS share. (CVE-2009-1439, Important)

  * several flaws were found in the way the Linux kernel CIFS implementation
  handles Unicode strings. CIFS clients convert Unicode strings sent by a
  server to their local character sets, and then write those strings into
  memory. If a malicious server sent a long enough string, it could write
  past the end of the target memory region and corrupt other memory areas,
  possibly leading to a denial of service or privilege escalation on the
  client mounting the CIFS share. (CVE-2009-1633, Important)

  These updated packages also fix the following bugs:

  * when using network bonding in the "balance-tlb" or "balance-alb" mode,
  the primary setting for the primary slave device was lost when said
  device was brought down (ifdown). Bringing the slave interface back up
  (ifup) did not restore the primary setting (the device was not made the
  active slave). (BZ#507563)

  * a bug in timer_interrupt() may have caused the system time to move up to
  two days or more into the future, or to be delayed for several minutes.
  This bug only affected Intel 64 and AMD64 systems that have the High
  Precision Event Timer (HPET) enabled in the BIOS, and could have caused
  problems for applications that require timing to be accurate. (BZ#508835)

  * a race condition was resolved in the Linux kernel block layer between
  show_partition() and rescan_partitions(). This could have caused a NULL
  pointer dereference in show_partition(), leading to a system crash (kernel
  panic). This issue was most likely to occur on systems running monitoring
  software that regularly scanned hard disk partitions, or from repeatedly
  running commands that probe for partition information. (BZ#512310)

  * previously, the Stratus memory tracker missed certain modified pages.
  With this update, information about the type of page (small page or
  huge page) is passed to the Stratus memory tracker, which resolves this
  issue. The fix for this issue does not affect systems that do not use
  memory tracking. (BZ#513182)

  * a bug may have caused a system crash when using the cciss driver, due to
  an uninitialized kernel structure. A reported case of this issue occurred
  after issuing consecutive SCSI TUR commands (sg_turs sends SCSI
  test-unit-ready commands in a loop). (BZ#513189)

  * a bug in the SCSI implementation caused "Aborted Command - internal
  target failure" errors to be sent to Device-Mapper Multipath, without
  retries, resulting in Device-Mapper Multipath marking the path as failed
  and making a path group switch. With this update, all errors that return a
  sense key in the SCSI mid layer (including "Aborted Command - internal
  target failure") are retried. (BZ#514007)

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The system must be rebooted for this
  update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1211.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1389", "CVE-2009-1439", "CVE-2009-1633");
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

if ( rpm_check( reference:"kernel-2.6.9-89.0.7.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-89.0.7.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-89.0.7.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-89.0.7.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-89.0.7.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-89.0.7.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-89.0.7.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-89.0.7.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-89.0.7.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.9-89.0.7.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-89.0.7.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-89.0.7.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-89.0.7.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-89.0.7.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-89.0.7.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-89.0.7.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-89.0.7.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-89.0.7.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
