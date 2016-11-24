
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31186);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0161: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0161");
 script_set_attribute(attribute: "description", value: '
  Updated cups packages that fix two security issues are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX(R) operating systems.

  A flaw was found in the way CUPS handled the addition and removal of remote
  shared printers via IPP. A remote attacker could send malicious UDP IPP
  packets causing the CUPS daemon to attempt to dereference already freed
  memory and crash. (CVE-2008-0597)

  A memory management flaw was found in the way CUPS handled the addition and
  removal of remote shared printers via IPP. When shared printer was
  removed, allocated memory was not properly freed, leading to a memory leak
  possibly causing CUPS daemon crash after exhausting available memory.
  (CVE-2008-0596)

  These issues were found during the investigation of CVE-2008-0882, which
  did not affect Red Hat Enterprise Linux 4.

  Note that the default configuration of CUPS on Red Hat Enterprise Linux
  4 allow requests of this type only from the local subnet.

  All CUPS users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0161.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0596", "CVE-2008-0597");
script_summary(english: "Check for the version of the cups packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cups-1.1.22-0.rc1.9.20.2.el4_6.5", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.22-0.rc1.9.20.2.el4_6.5", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.22-0.rc1.9.20.2.el4_6.5", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
