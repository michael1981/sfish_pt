
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12505);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-244: tripwire");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-244");
 script_set_attribute(attribute: "description", value: '
  Updated Tripwire packages that fix a format string security vulnerability
  are now available.

  Tripwire is a system integrity assessment tool.

  Paul Herman discovered a format string vulnerability in Tripwire version
  2.3.1 and earlier. If Tripwire is configured to send reports via email, a
  local user could gain privileges by creating a carefully crafted file. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0536 to this issue.

  Users of Tripwire are advised to upgrade to this erratum package which
  contains a backported security patch to correct this issue. The erratum
  package also contains some minor bug fixes.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-244.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0536");
script_summary(english: "Check for the version of the tripwire packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tripwire-2.3.1-18", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
