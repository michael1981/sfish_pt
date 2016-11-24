
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28364);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1059: pcre");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1059");
 script_set_attribute(attribute: "description", value: '
  Updated pcre packages that resolve several security issues are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  PCRE is a Perl-compatible regular expression library.

  Flaws were discovered in the way PCRE handles certain malformed regular
  expressions. If an application linked against PCRE, such as Konqueror,
  parses a malicious regular expression, it may have been possible to run
  arbitrary code as the user running the application.
  (CVE-2006-7225, CVE-2006-7226, CVE-2006-7228, CVE-2006-7230)

  Users of PCRE are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.

  Red Hat would like to thank Ludwig Nussel for reporting these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1059.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-7225", "CVE-2006-7226", "CVE-2006-7228", "CVE-2006-7230");
script_summary(english: "Check for the version of the pcre packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pcre-6.6-2.el5_1.7", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pcre-devel-6.6-2.el5_1.7", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
