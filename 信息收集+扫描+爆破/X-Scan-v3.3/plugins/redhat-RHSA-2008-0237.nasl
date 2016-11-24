
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32162);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0237: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0237");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues and several bugs
  are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  * the absence of a protection mechanism when attempting to access a
  critical section of code has been found in the Linux kernel open file
  descriptors control mechanism, fcntl. This could allow a local unprivileged
  user to simultaneously execute code, which would otherwise be protected
  against parallel execution. As well, a race condition when handling locks
  in the Linux kernel fcntl functionality, may have allowed a process
  belonging to a local unprivileged user to gain re-ordered access to the
  descriptor table. (CVE-2008-1669, Important)

  * on AMD64 architectures, the possibility of a kernel crash was discovered
  by testing the Linux kernel process-trace ability. This could allow a local
  unprivileged user to cause a denial of service (kernel crash).
  (CVE-2008-1615, Important)

  * the absence of a protection mechanism when attempting to access a
  critical section of code, as well as a race condition, have been found
  in the Linux kernel file system event notifier, dnotify. This could allow a
  local unprivileged user to get inconsistent data, or to send arbitrary
  signals to arbitrary system processes. (CVE-2008-1375, Important)

  Red Hat would like to thank Nick Piggin for responsibly disclosing the
  following issue:

  * when accessing kernel memory locations, certain Linux kernel drivers
  registering a fault handler did not perform required range checks. A local
  unprivileged user could use this flaw to gain read or write access to
  arbitrary kernel memory, or possibly cause a kernel crash.
  (CVE-2008-0007, Important)

  * the possibility of a kernel crash was found in the Linux kernel IPsec
  protocol implementation, due to improper handling of fragmented ESP
  packets. When an attacker controlling an intermediate router fragmented
  these packets into very small pieces, it would cause a kernel crash on the
  receiving node during packet reassembly. (CVE-2007-6282, Important)

  * a flaw in the MOXA serial driver could allow a local unprivileged user
  to perform privileged operations, such as replacing firmware.
  (CVE-2005-0504, Important)

  As well, these updated packages fix the following bugs:

  * multiple buffer overflows in the neofb driver have been resolved. It was
  not possible for an unprivileged user to exploit these issues, and as such,
  they have not been handled as security issues.

  * a kernel panic, due to inconsistent detection of AGP aperture size, has
  been resolved.

  * a race condition in UNIX domain sockets may have caused "recv()" to
  return zero. In clustered configurations, this may have caused unexpected
  failovers.

  * to prevent link storms, network link carrier events were delayed by up to
  one second, causing unnecessary packet loss. Now, link carrier events are
  scheduled immediately.

  * a client-side race on blocking locks caused large time delays on NFS file
  systems.

  * in certain situations, the libATA sata_nv driver may have sent commands
  with duplicate tags, which were rejected by SATA devices. This may have
  caused infinite reboots.

  * running the "service network restart" command may have caused networking
  to fail.

  * a bug in NFS caused cached information about directories to be stored
  for too long, causing wrong attributes to be read.

  * on systems with a large highmem/lowmem ratio, NFS write performance may
  have been very slow when using small files.

  * a bug, which caused network hangs when the system clock was wrapped
  around zero, has been resolved.

  Red Hat Enterprise Linux 4 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0237.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0504", "CVE-2007-6282", "CVE-2008-0007", "CVE-2008-1375", "CVE-2008-1615", "CVE-2008-1669");
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

if ( rpm_check( reference:"kernel-2.6.9-67.0.15.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-67.0.15.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-67.0.15.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-67.0.15.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-67.0.15.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-67.0.15.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-67.0.15.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-67.0.15.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-67.0.15.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
