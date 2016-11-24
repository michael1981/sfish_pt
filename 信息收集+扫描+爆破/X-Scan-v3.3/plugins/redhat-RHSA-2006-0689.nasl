
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22523);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0689: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0689");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 4 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues described
  below:

  * a flaw in the SCTP support that allowed a local user to cause a denial of
  service (crash) with a specific SO_LINGER value. (CVE-2006-4535, Important)

  * a flaw in the hugepage table support that allowed a local user to cause a
  denial of service (crash). (CVE-2005-4811, Important)

  * a flaw in the mprotect system call that allowed setting write permission
  for a read-only attachment of shared memory. (CVE-2006-2071, Moderate)

  * a flaw in HID0[31] (en_attn) register handling on PowerPC 970 systems
  that allowed a local user to cause a denial of service. (crash)
  (CVE-2006-4093, Moderate)

  * a flaw in the perfmon support of Itanium systems that allowed a local
  user to cause a denial of service by consuming all file descriptors.
  (CVE-2006-3741, Moderate)

  * a flaw in the ATM subsystem. On systems with installed ATM hardware and
  configured ATM support, a remote user could cause a denial of service
  (panic) by accessing socket buffers memory after freeing them.
  (CVE-2006-4997, Moderate)

  * a flaw in the DVB subsystem. On systems with installed DVB hardware and
  configured DVB support, a remote user could cause a denial of service
  (panic) by sending a ULE SNDU packet with length of 0. (CVE-2006-4623, Low)

  * an information leak in the network subsystem that possibly allowed a
  local user to read sensitive data from kernel memory. (CVE-2006-0039, Low)

  In addition, two bugfixes for the IPW-2200 wireless driver were included.
  The first one ensures that wireless management applications correctly
  identify IPW-2200 controlled devices, while the second fix ensures that
  DHCP requests using the IPW-2200 operate correctly.

  Red Hat would like to thank Olof Johansson, Stephane Eranian and Solar
  Designer for reporting issues fixed in this erratum.

  All Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0689.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-4811", "CVE-2006-0039", "CVE-2006-2071", "CVE-2006-3741", "CVE-2006-4093", "CVE-2006-4535", "CVE-2006-4623", "CVE-2006-4997");
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

if ( rpm_check( reference:"kernel-2.6.9-42.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-42.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-42.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-42.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-42.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-42.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-42.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
