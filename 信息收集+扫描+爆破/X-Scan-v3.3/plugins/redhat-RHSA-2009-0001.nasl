
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35323);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2009-0001:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0001");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix a number of security issues are now
  available for Red Hat Enterprise Linux 2.1 running on 32-bit architectures.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  * a flaw was found in the IPv4 forwarding base. This could allow a local,
  unprivileged user to cause a denial of service. (CVE-2007-2172,
  Important)

  * a flaw was found in the handling of process death signals. This allowed a
  local, unprivileged user to send arbitrary signals to the suid-process
  executed by that user. Successful exploitation of this flaw depends on the
  structure of the suid-program and its signal handling. (CVE-2007-3848,
  Important)

  * when accessing kernel memory locations, certain Linux kernel drivers
  registering a fault handler did not perform required range checks. A local,
  unprivileged user could use this flaw to gain read or write access to
  arbitrary kernel memory, or possibly cause a denial of service.
  (CVE-2008-0007, Important)

  * a possible kernel memory leak was found in the Linux kernel Simple
  Internet Transition (SIT) INET6 implementation. This could allow a local,
  unprivileged user to cause a denial of service. (CVE-2008-2136, Important)

  * missing capability checks were found in the SBNI WAN driver which could
  allow a local, unprivileged user to bypass intended capability
  restrictions. (CVE-2008-3525, Important)

  * a flaw was found in the way files were written using truncate() or
  ftruncate(). This could allow a local, unprivileged user to acquire the
  privileges of a different group and obtain access to sensitive information.
  (CVE-2008-4210, Important)

  * a race condition in the mincore system core allowed a local, unprivileged
  user to cause a denial of service. (CVE-2006-4814, Moderate)

  * a flaw was found in the aacraid SCSI driver. This allowed a local,
  unprivileged user to make ioctl calls to the driver which should otherwise
  be restricted to privileged users. (CVE-2007-4308, Moderate)

  * two buffer overflow flaws were found in the Integrated Services Digital
  Network (ISDN) subsystem. A local, unprivileged user could use these flaws
  to cause a denial of service. (CVE-2007-6063, CVE-2007-6151, Moderate)

  * a flaw was found in the way core dump files were created. If a local,
  unprivileged user could make a root-owned process dump a core file into a
  user-writable directory, the user could gain read access to that core file,
  potentially compromising sensitive information. (CVE-2007-6206, Moderate)

  * a deficiency was found in the Linux kernel virtual file system (VFS)
  implementation. This could allow a local, unprivileged user to attempt file
  creation within deleted directories, possibly causing a denial of service.
  (CVE-2008-3275, Moderate)

  All users of Red Hat Enterprise Linux 2.1 on 32-bit architectures should
  upgrade to these updated packages which address these vulnerabilities. For
  this update to take effect, the system must be rebooted.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0001.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4814", "CVE-2007-2172", "CVE-2007-3848", "CVE-2007-4308", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2008-0007", "CVE-2008-2136", "CVE-2008-3275", "CVE-2008-3525", "CVE-2008-4210");
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

if ( rpm_check( reference:"  kernel-2.4.9-e.74.athlon.rpm               17c281132f3e12817141866f1b97208b", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.9-e.74", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.74", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.74", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.74", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.74", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.74", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.74.athlon.rpm           115baee1b0a4cdff19703687bfde8157", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.74", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.74", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.74", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
