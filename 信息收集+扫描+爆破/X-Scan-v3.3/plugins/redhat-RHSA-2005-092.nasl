
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17183);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-092: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-092");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  This advisory includes fixes for several security issues:

  iSEC Security Research discovered multiple vulnerabilities in the IGMP
  functionality. These flaws could allow a local user to cause a denial of
  service (crash) or potentially gain privileges. Where multicast
  applications are being used on a system, these flaws may also allow remote
  users to cause a denial of service. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-1137 to
  this issue.

  iSEC Security Research discovered a flaw in the page fault handler code
  that could lead to local users gaining elevated (root) privileges on
  multiprocessor machines. (CAN-2005-0001)

  iSEC Security Research discovered a VMA handling flaw in the uselib(2)
  system call of the Linux kernel. A local user could make use of this
  flaw to gain elevated (root) privileges. (CAN-2004-1235)

  A flaw affecting the OUTS instruction on the AMD64 and Intel EM64T
  architecture was discovered. A local user could use this flaw to write to
  privileged IO ports. (CAN-2005-0204)

  The Direct Rendering Manager (DRM) driver in Linux kernel 2.6 does not
  properly check the DMA lock, which could allow remote attackers or local
  users to cause a denial of service (X Server crash) or possibly modify the
  video output. (CAN-2004-1056)

  OGAWA Hirofumi discovered incorrect tables sizes being used in the
  filesystem Native Language Support ASCII translation table. This could
  lead to a denial of service (system crash). (CAN-2005-0177)

  Michael Kerrisk discovered a flaw in the 2.6.9 kernel which allows users to
  unlock arbitrary shared memory segments. This flaw could lead to
  applications not behaving as expected. (CAN-2005-0176)

  Improvements in the POSIX signal and tty standards compliance exposed
  a race condition. This flaw can be triggered accidentally by threaded
  applications or deliberately by a malicious user and can result in a
  denial of service (crash) or in occasional cases give access to a small
  random chunk of kernel memory. (CAN-2005-0178)

  The PaX team discovered a flaw in mlockall introduced in the 2.6.9 kernel.
  An unprivileged user could use this flaw to cause a denial of service
  (CPU and memory consumption or crash). (CAN-2005-0179)

  Brad Spengler discovered multiple flaws in sg_scsi_ioctl in the 2.6 kernel.
  An unprivileged user may be able to use this flaw to cause a denial of
  service (crash) or possibly other actions. (CAN-2005-0180)

  Kirill Korotaev discovered a missing access check regression in the Red Hat
  Enterprise Linux 4 kernel 4GB/4GB split patch. On systems using the
  hugemem kernel, a local unprivileged user could use this flaw to cause a
  denial of service (crash). (CAN-2005-0090)

  A flaw in the Red Hat Enterprise Linux 4 kernel 4GB/4GB split patch can
  allow syscalls to read and write arbitrary kernel memory. On systems using
  the hugemem kernel, a local unprivileged user could use this flaw to gain
  privileges. (CAN-2005-0091)

  An additional flaw in the Red Hat Enterprise Linux 4 kernel 4GB/4GB split
  patch was discovered. On x86 systems using the hugemem kernel, a local
  unprivileged user may be able to use this flaw to cause a denial of service
  (crash). (CAN-2005-0092)

  All Red Hat Enterprise Linux 4 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-092.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1056", "CVE-2004-1137", "CVE-2004-1235", "CVE-2005-0001", "CVE-2005-0090", "CVE-2005-0091", "CVE-2005-0092", "CVE-2005-0176", "CVE-2005-0177", "CVE-2005-0178", "CVE-2005-0179", "CVE-2005-0180", "CVE-2005-0204");
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

if ( rpm_check( reference:"kernel-2.6.9-5.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-5.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-5.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-5.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-5.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-5.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-5.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
