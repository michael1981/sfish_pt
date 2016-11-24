
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12341);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2002-291: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-291");
 script_set_attribute(attribute: "description", value: '
  Updated Ethereal packages are available which fix various security issues.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  Ethereal is a package designed for monitoring network traffic on your
  system. Several security issues have been found in the Ethereal packages
  distributed with Red Hat Linux Advanced Server 2.1.

  Multiple errors involving signed integers in the BGP dissector in Ethereal
  0.9.7 and earlier allow remote attackers to cause a denial of service
  (infinite loop) via malformed messages. This problem was discovered by
  Silvio Cesare. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2002-1355 to this issue.

  Ethereal 0.9.7 and earlier allows remote attackers to cause a denial
  of service (crash) and possibly execute arbitrary code via malformed
  packets to the LMP, PPP, or TDS dissectors. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2002-1356 to
  this issue.

  Users of Ethereal should update to the errata packages containing Ethereal
  version 0.9.8 which is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-291.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1355", "CVE-2002-1356");
script_summary(english: "Check for the version of the ethereal packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ethereal-0.9.8-0.AS21.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.9.8-0.AS21.0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
