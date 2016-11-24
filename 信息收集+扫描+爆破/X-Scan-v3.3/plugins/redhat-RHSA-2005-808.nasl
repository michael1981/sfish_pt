
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20104);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-808: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-808");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and a page
  attribute mapping bug are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the
  Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  An issue was discovered that affects how page attributes are changed by the
  kernel. Video drivers, which sometimes map kernel pages with a different
  caching policy than write-back, are now expected to function correctly.
  This change affects the x86, AMD64, and Intel EM64T architectures.

  In addition the following security bugs were fixed:

  The set_mempolicy system call did not check for negative numbers in the
  policy field. An unprivileged local user could use this flaw to cause a
  denial of service (system panic). (CVE-2005-3053)

  A flaw in ioremap handling on AMD 64 and Intel EM64T systems. An
  unprivileged local user could use this flaw to cause a denial of service or
  minor information leak. (CVE-2005-3108)

  A race condition in the ebtables netfilter module. On a SMP system that is
  operating under a heavy load this flaw may allow remote attackers to cause
  a denial of service (crash). (CVE-2005-3110)

  A memory leak was found in key handling. An unprivileged local user could
  use this flaw to cause a denial of service. (CVE-2005-3119)

  A flaw in the Orinoco wireless driver. On systems running the vulnerable
  drive, a remote attacker could send carefully crafted packets which would
  divulge the contents of uninitialized kernel memory. (CVE-2005-3180)

  A memory leak was found in the audit system. An unprivileged local user
  could use this flaw to cause a denial of service. (CVE-2005-3181)

  All Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-808.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3053", "CVE-2005-3108", "CVE-2005-3110", "CVE-2005-3119", "CVE-2005-3180", "CVE-2005-3181");
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

if ( rpm_check( reference:"kernel-2.6.9-22.0.1.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-22.0.1.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-22.0.1.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-22.0.1.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-22.0.1.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-22.0.1.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-22.0.1.EL", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
