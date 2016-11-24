
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25605);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0488: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0488");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and bugs in the
  Red Hat Enterprise Linux 4 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues described
  below:

  * a flaw in the connection tracking support for SCTP that allowed a remote
  user to cause a denial of service by dereferencing a NULL pointer.
  (CVE-2007-2876, Important)

  * a flaw in the mount handling routine for 64-bit systems that allowed a
  local user to cause denial of service (crash). (CVE-2006-7203, Important)

  * a flaw in the IPv4 forwarding base that allowed a local user to cause an
  out-of-bounds access. (CVE-2007-2172, Important)

  * a flaw in the PPP over Ethernet implementation that allowed a local user
  to cause a denial of service (memory consumption) by creating a socket
  using connect and then releasing it before the PPPIOCGCHAN ioctl has been
  called. (CVE-2007-2525, Important)

  * a flaw in the fput ioctl handling of 32-bit applications running on
  64-bit platforms that allowed a local user to cause a denial of service
  (panic). (CVE-2007-0773, Important)

  * a flaw in the NFS locking daemon that allowed a local user to cause
  denial of service (deadlock). (CVE-2006-5158, Moderate)

  * a flaw in the sysfs_readdir function that allowed a local user to cause a
  denial of service by dereferencing a NULL pointer. (CVE-2007-3104, Moderate)

  * a flaw in the core-dump handling that allowed a local user to create core
  dumps from unreadable binaries via PT_INTERP. (CVE-2007-0958, Low)

  * a flaw in the Bluetooth subsystem that allowed a local user to trigger an
  information leak. (CVE-2007-1353, Low)

  In addition, the following bugs were addressed:

  * the NFS could recurse on the same spinlock. Also, NFS, under certain
  conditions, did not completely clean up Posix locks on a file close,
  leading to mount failures.

  * the 32bit compatibility didn\'t return to userspace correct values for the
  rt_sigtimedwait system call.

  * the count for unused inodes could be incorrect at times, resulting in
  dirty data not being written to disk in a timely manner.

  * the cciss driver had an incorrect disk size calculation (off-by-one
  error) which prevented disk dumps.

  Red Hat would like to thank Ilja van Sprundel and the OpenVZ Linux kernel
  team for reporting issues fixed in this erratum.

  All Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0488.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-5158", "CVE-2006-7203", "CVE-2007-0773", "CVE-2007-0958", "CVE-2007-1353", "CVE-2007-2172", "CVE-2007-2525", "CVE-2007-2876", "CVE-2007-3104");
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

if ( rpm_check( reference:"kernel-2.6.9-55.0.2.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-55.0.2.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-55.0.2.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-55.0.2.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-55.0.2.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-55.0.2.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-55.0.2.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-55.0.2.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-55.0.2.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
