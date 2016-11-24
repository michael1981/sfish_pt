
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35190);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0973:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0973");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that resolve several security issues and fix
  various bugs are now available for Red Hat Enterprise Linux 3.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update addresses the following security issues:

  * Tavis Ormandy discovered a deficiency in the Linux kernel 32-bit and
  64-bit emulation. This could allow a local, unprivileged user to prepare
  and run a specially-crafted binary which would use this deficiency to leak
  uninitialized and potentially sensitive data. (CVE-2008-0598, Important)

  * a possible kernel memory leak was found in the Linux kernel Simple
  Internet Transition (SIT) INET6 implementation. This could allow a local,
  unprivileged user to cause a denial of service. (CVE-2008-2136, Important)

  * missing capability checks were found in the SBNI WAN driver which could
  allow a local user to bypass intended capability restrictions.
  (CVE-2008-3525, Important)

  * the do_truncate() and generic_file_splice_write() functions did not clear
  the setuid and setgid bits. This could allow a local, unprivileged user to
  obtain access to privileged information. (CVE-2008-4210, Important)

  * a buffer overflow flaw was found in Integrated Services Digital Network
  (ISDN) subsystem. A local, unprivileged user could use this flaw to cause a
  denial of service. (CVE-2007-6063, Moderate)

  * multiple NULL pointer dereferences were found in various Linux kernel
  network drivers. These drivers were missing checks for terminal validity,
  which could allow privilege escalation. (CVE-2008-2812, Moderate)

  * a deficiency was found in the Linux kernel virtual filesystem (VFS)
  implementation. This could allow a local, unprivileged user to attempt file
  creation within deleted directories, possibly causing a denial of service.
  (CVE-2008-3275, Moderate)

  This update also fixes the following bugs:

  * the incorrect kunmap function was used in nfs_xdr_readlinkres. kunmap()
  was used where kunmap_atomic() should have been. As a consequence, if an
  NFSv2 or NFSv3 server exported a volume containing a symlink which included
  a path equal to or longer than the local system\'s PATH_MAX, accessing the
  link caused a kernel oops. This has been corrected in this update.

  * mptctl_gettargetinfo did not check if pIoc3 was NULL before using it as a
  pointer. This caused a kernel panic in mptctl_gettargetinfo in some
  circumstances. A check has been added which prevents this.

  * lost tick compensation code in the timer interrupt routine triggered
  without apparent cause. When running as a fully-virtualized client, this
  spurious triggering caused the 64-bit version of Red Hat Enterprise Linux 3
  to present highly inaccurate times. With this update the lost tick
  compensation code is turned off when the operating system is running as a
  fully-virtualized client under Xen or VMWare  .

  All Red Hat Enterprise Linux 3 users should install this updated kernel
  which addresses these vulnerabilities and fixes these bugs.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0973.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-6063", "CVE-2008-0598", "CVE-2008-2136", "CVE-2008-2812", "CVE-2008-3275", "CVE-2008-3525", "CVE-2008-4210");
script_summary(english: "Check for the version of the   kernel packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"  kernel-2.4.21-58.EL.athlon.rpm                        10ce0bd698e40ee8962558e0483ce638", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-58.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-58.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-58.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-58.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-58.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-58.EL.athlon.rpm                    66a4c22852c3d712a90189531260fb6b", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-58.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-58.EL.athlon.rpm        91933f1fe4e8b0d1dbb5e837880b68a5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-58.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-58.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-58.EL.athlon.rpm            7b57ec05f49b1a658fd3ac8d9893cfc1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-58.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
