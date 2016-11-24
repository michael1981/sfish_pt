
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29204);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1095: htdig");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1095");
 script_set_attribute(attribute: "description", value: '
  Updated htdig packages that resolve a security issue are now available for
  Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The ht://Dig system is a complete World Wide Web indexing and searching
  system for a small domain or intranet.

  A cross-site scripting flaw was discovered in a htdig search page. An
  attacker could construct a carefully crafted URL, which once visited by an
  unsuspecting user, could cause a user\'s Web browser to execute malicious
  script in the context of the visited htdig search Web page. (CVE-2007-6110)

  Users of htdig are advised to upgrade to these updated packages, which
  contain backported patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1095.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-6110");
script_summary(english: "Check for the version of the htdig packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"htdig-3.2.0b6-9.0.1.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"htdig-web-3.2.0b6-9.0.1.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"htdig-3.2.0b6-4.el4_6", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"htdig-web-3.2.0b6-4.el4_6", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
