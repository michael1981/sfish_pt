
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17589);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-235: mailman");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-235");
 script_set_attribute(attribute: "description", value: '
  An updated mailman package that corrects a cross-site scripting flaw is now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Mailman manages electronic mail discussion and e-newsletter lists.

  A cross-site scripting (XSS) flaw in the driver script of mailman prior to
  version 2.1.5 could allow remote attackers to execute scripts as other web
  users. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CAN-2004-1177 to this issue.

  Users of mailman should update to this erratum package, which corrects this
  issue by turning on STEALTH_MODE by default and using Utils.websafe() to
  quote the html.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-235.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1177");
script_summary(english: "Check for the version of the mailman packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mailman-2.1.5-25.rhel3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5-33.rhel4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
