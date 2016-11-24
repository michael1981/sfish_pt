
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20858);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0200: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0200");
 script_set_attribute(attribute: "description", value: '
  An updated firefox package that fixes several security bugs is now
  available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Igor Bukanov discovered a bug in the way Firefox\'s Javascript interpreter
  derefernces objects. If a user visits a malicious web page, Firefox could
  crash or execute arbitrary code as the user running Firefox. The Common
  Vulnerabilities and Exposures project assigned the name CVE-2006-0292 to
  this issue.

  moz_bug_r_a4 discovered a bug in Firefox\'s XULDocument.persist() function.
  A malicious web page could inject arbitrary RDF data into a user\'s
  localstore.rdf file, which can cause Firefox to execute arbitrary
  javascript when a user runs Firefox. (CVE-2006-0296)

  A denial of service bug was found in the way Firefox saves history
  information. If a user visits a web page with a very long title, it is
  possible Firefox will crash or take a very long time the next time it is
  run. (CVE-2005-4134)

  This update also fixes a bug when using XSLT to transform documents.
  Passing DOM Nodes as parameters to functions expecting an xsl:param could
  cause Firefox to throw an exception.

  Users of Firefox are advised to upgrade to this updated package, which
  contains backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0200.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0296");
script_summary(english: "Check for the version of the firefox packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"firefox-1.0.7-1.4.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
