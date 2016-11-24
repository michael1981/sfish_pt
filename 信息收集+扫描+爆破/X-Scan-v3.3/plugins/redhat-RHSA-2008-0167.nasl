
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31595);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0167: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0167");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues and several bugs
  are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  A buffer overflow flaw was found in the CIFS virtual file system. A
  remote authenticated user could issue a request that could lead to
  a denial of service. (CVE-2007-5904, Moderate)

  As well, these updated packages fix the following bugs:

  * a bug was found in the Linux kernel audit subsystem. When the audit
  daemon was setup to log the execve system call with a large number
  of arguments, the kernel could run out out memory while attempting to
  create audit log messages. This could cause a kernel panic. In these
  updated packages, large audit messages are split into acceptable sizes,
  which resolves this issue.

  * on certain Intel chipsets, it was not possible to load the acpiphp
  module using the "modprobe acpiphp" command. Because the acpiphp module
  did not recurse across PCI bridges, hardware detection for PCI hot plug
  slots failed. In these updated packages, hardware detection works
  correctly.

  * on IBM System z architectures that run the IBM z/VM hypervisor, the IBM
  eServer zSeries HiperSockets network interface (layer 3) allowed ARP
  packets to be sent and received, even when the "NOARP" flag was set. These
  ARP packets caused problems for virtual machines.

  * it was possible for the iounmap function to sleep while holding a lock.
  This may have caused a deadlock for drivers and other code that uses the
  iounmap function. In these updated packages, the lock is dropped before
  the sleep code is called, which resolves this issue.

  Red Hat Enterprise Linux 4 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0167.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5904");
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

if ( rpm_check( reference:"kernel-2.6.9-67.0.7.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-67.0.7.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-67.0.7.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-67.0.7.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-67.0.7.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-67.0.7.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-67.0.7.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-67.0.7.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-67.0.7.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
