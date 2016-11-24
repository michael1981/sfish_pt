
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12360);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-045: w");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-045");
 script_set_attribute(attribute: "description", value: '
  Updated W3M packages are available that fix two cross-site scripting
  issues.

  W3M is a pager with Web browsing capabilities. Two cross-site scripting
  (XSS) issues have been found in W3M.

  An XSS vulnerability in W3M 0.3.2 allows remote attackers to insert
  arbitrary HTML and Web script into frames. Frames are disabled by default
  in the version of W3M shipped with Red Hat Linux Advanced Server and Red
  Hat Linux Advanced Workstation. Therefore, this problem will not appear as
  long as users do not use W3M with the -F option, or enable frame support in
  either the /etc/w3m/w3mconfig or ~/.w3m/config configuration files. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2002-1335 to this issue.

  An XSS vulnerability in versions of W3M before 0.3.2.2 allows attackers to
  insert arbitrary HTML and Web script into image attributes. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2002-1348 to this issue.

  Users of W3M are advised to upgrade to the updated packages containing W3M
  0.2.1 and a patch to correct these vulnerabilities.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-045.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1335", "CVE-2002-1348");
script_summary(english: "Check for the version of the w packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"w3m-0.2.1-11.AS21.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
