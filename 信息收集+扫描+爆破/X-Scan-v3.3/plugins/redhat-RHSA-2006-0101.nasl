
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20732);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0101: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0101");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 4 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues
  described below:

  - a flaw in network IGMP processing that a allowed a remote user on the
  local network to cause a denial of service (disabling of multicast reports)
  if the system is running multicast applications (CVE-2002-2185, moderate)

  - a flaw which allowed a local user to write to firmware on read-only
  opened /dev/cdrom devices (CVE-2004-1190, moderate)

  - a flaw in gzip/zlib handling internal to the kernel that may allow a
  local user to cause a denial of service (crash) (CVE-2005-2458, low)

  - a flaw in procfs handling during unloading of modules that allowed a
  local user to cause a denial of service or potentially gain privileges
  (CVE-2005-2709, moderate)

  - a flaw in the SCSI procfs interface that allowed a local user to cause a
  denial of service (crash) (CVE-2005-2800, moderate)

  - a flaw in 32-bit-compat handling of the TIOCGDEV ioctl that allowed
  a local user to cause a denial of service (crash) (CVE-2005-3044, important)

  - a race condition when threads share memory mapping that allowed local
  users to cause a denial of service (deadlock) (CVE-2005-3106, important)

  - a flaw when trying to mount a non-hfsplus filesystem using hfsplus that
  allowed local users to cause a denial of service (crash) (CVE-2005-3109,
  moderate)

  - a minor info leak with the get_thread_area() syscall that allowed
  a local user to view uninitialized kernel stack data (CVE-2005-3276, low)

  - a flaw in mq_open system call that allowed a local user to cause a denial
  of service (crash) (CVE-2005-3356, important)

  - a flaw in set_mempolicy that allowed a local user on some 64-bit
  architectures to cause a denial of service (crash) (CVE-2005-3358, important)

  - a flaw in the auto-reap of child processes that allowed a local user to
  cause a denial of service (crash) (CVE-2005-3784, important)

  - a flaw in the IPv6 flowlabel code that allowed a local user to cause a
  denial of service (crash) (CVE-2005-3806, important)

  - a flaw in network ICMP processing that allowed a local user to cause
  a denial of service (memory exhaustion) (CVE-2005-3848, important)

  - a flaw in file lease time-out handling that allowed a local user to cause
  a denial of service (log file overflow) (CVE-2005-3857, moderate)

  - a flaw in network IPv6 xfrm handling that allowed a local user to
  cause a denial of service (memory exhaustion) (CVE-2005-3858, important)

  - a flaw in procfs handling that allowed a local user to read kernel memory
  (CVE-2005-4605, important)

  All Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0101.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-2185", "CVE-2004-1190", "CVE-2005-2458", "CVE-2005-2709", "CVE-2005-2800", "CVE-2005-3044", "CVE-2005-3106", "CVE-2005-3109", "CVE-2005-3276", "CVE-2005-3356", "CVE-2005-3358", "CVE-2005-3784", "CVE-2005-3806", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858", "CVE-2005-4605");
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

if ( rpm_check( reference:"kernel-2.6.9-22.0.2.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-22.0.2.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-22.0.2.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-22.0.2.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-22.0.2.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-22.0.2.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-22.0.2.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
