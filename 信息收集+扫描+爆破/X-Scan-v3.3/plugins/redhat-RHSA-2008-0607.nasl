
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33570);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0607: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0607");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix a security issue and several bugs are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issue:

  * a possible kernel memory leak was found in the Linux kernel Simple
  Internet Transition (SIT) INET6 implementation. This could allow a local
  unprivileged user to cause a denial of service. (CVE-2008-2136, Important)

  As well, these updated packages fix the following bugs:

  * a possible kernel hang on hugemem systems, due to a bug in NFS, which may
  have caused systems to become unresponsive, has been resolved.

  * an inappropriate exit condition occurred in the architecture-specific
  "mmap()" realization, which fell into an infinite loop under certain
  conditions. On 64-bit systems, this issue may have manifested itself to
  users as a soft lockup, or process hangs.

  * due to a bug in hardware initialization in the "ohci_hcd" kernel module,
  the kernel may have failed with a NULL pointer dereference. On 64-bit
  PowerPC systems, this may have caused booting to fail, and drop to xmon. On
  other platforms, a kernel oops occurred.

  * due to insufficient locks in task termination code, a panic may have
  occurred in the "sys_times()" system call on SMP machines.

  Red Hat Enterprise Linux 4 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0607.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2136");
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

if ( rpm_check( reference:"kernel-2.6.9-67.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-67.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-67.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-67.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-67.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-67.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-67.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-67.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-67.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
