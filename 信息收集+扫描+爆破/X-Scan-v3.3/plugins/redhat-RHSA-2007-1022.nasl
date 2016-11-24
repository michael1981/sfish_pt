
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36860);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2007-1022: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1022");
 script_set_attribute(attribute: "description", value: '
  Updated cups packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX(R) operating systems.

  Alin Rad Pop discovered several flaws in the handling of PDF files. An
  attacker could create a malicious PDF file that would cause CUPS to crash
  or potentially execute arbitrary code when printed.
  (CVE-2007-4352, CVE-2007-5392, CVE-2007-5393)

  Alin Rad Pop discovered a flaw in in the way CUPS handles certain IPP tags.
  A remote attacker who is able to connect to the IPP TCP port could send a
  malicious request causing the CUPS daemon to crash. (CVE-2007-4351)

  A flaw was found in the way CUPS handled SSL negotiation. A remote attacker
  capable of connecting to the CUPS daemon could cause CUPS to crash.
  (CVE-2007-4045)

  All CUPS users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1022.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4045", "CVE-2007-4351", "CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
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

if ( rpm_check( reference:"cups-1.1.22-0.rc1.9.20.2.el4_5.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.22-0.rc1.9.20.2.el4_5.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.22-0.rc1.9.20.2.el4_5.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
