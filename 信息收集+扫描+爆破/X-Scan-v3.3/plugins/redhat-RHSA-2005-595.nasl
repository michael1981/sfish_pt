
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19381);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-595: squirrelmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-595");
 script_set_attribute(attribute: "description", value: '
  An updated squirrelmail package that fixes two security issues is now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  [Updated 04 Aug 2005]
  The previous SquirrelMail package released with this errata contained a bug
  which rendered the addressbook unusable. The erratum has been updated with
  a package which corrects this issue.

  SquirrelMail is a standards-based webmail package written in PHP4.

  A bug was found in the way SquirrelMail handled the $_POST variable. If a
  user is tricked into visiting a malicious URL, the user\'s SquirrelMail
  preferences could be read or modified. The Common Vulnerabilities and
  Exposures project assigned the name CAN-2005-2095 to this issue.

  Several cross-site scripting bugs were discovered in SquirrelMail. An
  attacker could inject arbitrary Javascript or HTML content into
  SquirrelMail pages by tricking a user into visiting a carefully crafted
  URL, or by sending them a carefully constructed HTML email message. The
  Common Vulnerabilities and Exposures project assigned the name
  CAN-2005-1769 to this issue.

  All users of SquirrelMail should upgrade to this updated package, which
  contains backported patches that resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-595.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1769", "CVE-2005-2095");
script_summary(english: "Check for the version of the squirrelmail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squirrelmail-1.4.3a-11.EL3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.3a-12.EL4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
