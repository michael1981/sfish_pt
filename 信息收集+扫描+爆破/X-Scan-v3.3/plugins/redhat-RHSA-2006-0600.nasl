
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22330);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0600: mailman");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0600");
 script_set_attribute(attribute: "description", value: '
  Updated mailman packages that fix security issues are now available for Red
  Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Mailman is a program used to help manage email discussion lists.

  A flaw was found in the way Mailman handled MIME multipart messages. An
  attacker could send a carefully crafted MIME multipart email message to a
  mailing list run by Mailman which caused that particular mailing list
  to stop working. (CVE-2006-2941)

  Several cross-site scripting (XSS) issues were found in Mailman. An
  attacker could exploit these issues to perform cross-site scripting attacks
  against the Mailman administrator. (CVE-2006-3636)

  Red Hat would like to thank Barry Warsaw for disclosing these
  vulnerabilities.

  Users of Mailman should upgrade to these updated packages, which contain
  backported patches to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0600.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-2941", "CVE-2006-3636");
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

if ( rpm_check( reference:"mailman-2.1.5.1-25.rhel3.7", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5.1-34.rhel4.5", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
