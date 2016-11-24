
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30140);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0055: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0055");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and a bug in the
  Red Hat Enterprise Linux 4 kernel are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated kernel packages fix the following security issues:

  A flaw was found in the virtual filesystem (VFS). A local unprivileged
  user could truncate directories to which they had write permission; this
  could render the contents of the directory inaccessible. (CVE-2008-0001,
  Important)

  A flaw was found in the implementation of ptrace. A local unprivileged user
  could trigger this flaw and possibly cause a denial of service (system
  hang). (CVE-2007-5500, Important)

  A flaw was found in the way the Red Hat Enterprise Linux 4 kernel handled
  page faults when a CPU used the NUMA method for accessing memory on Itanium
  architectures. A local unprivileged user could trigger this flaw and cause
  a denial of service (system panic). (CVE-2007-4130, Important)

  A possible NULL pointer dereference was found in the chrp_show_cpuinfo
  function when using the PowerPC architecture. This may have allowed a local
  unprivileged user to cause a denial of service (crash).
  (CVE-2007-6694, Moderate)

  A flaw was found in the way core dump files were created. If a local user
  can get a root-owned process to dump a core file into a directory, which
  the user has write access to, they could gain read access to that core
  file. This could potentially grant unauthorized access to sensitive
  information. (CVE-2007-6206, Moderate)

  Two buffer overflow flaws were found in the Linux kernel ISDN subsystem. A
  local unprivileged user could use these flaws to cause a denial of
  service. (CVE-2007-6063, CVE-2007-6151, Moderate)

  As well, these updated packages fix the following bug:

  * when moving volumes that contain multiple segments, and a mirror segment
  is not the first in the mapping table, running the "pvmove /dev/[device]
  /dev/[device]" command caused a kernel panic. A "kernel: Unable to handle
  kernel paging request at virtual address [address]" error was logged by
  syslog.

  Red Hat Enterprise Linux 4 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0055.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4130", "CVE-2007-5500", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6694", "CVE-2008-0001");
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

if ( rpm_check( reference:"kernel-2.6.9-67.0.4.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-67.0.4.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-67.0.4.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-67.0.4.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-67.0.4.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-67.0.4.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-67.0.4.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-67.0.4.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-67.0.4.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
