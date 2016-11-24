
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18555);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-517: HelixPlayer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-517");
 script_set_attribute(attribute: "description", value: '
  An updated HelixPlayer package that fixes a buffer overflow issue is now
  available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  HelixPlayer is a media player.

  A buffer overflow bug was found in the way HelixPlayer processes SMIL
  files.
  An attacker could create a specially crafted SMIL file, which when combined
  with a malicious web server, could execute arbitrary code when opened by a
  user. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2005-1766 to this issue.

  All users of HelixPlayer are advised to upgrade to this updated package,
  which contains HelixPlayer version 10.0.5 and is not vulnerable to this
  issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-517.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1766");
script_summary(english: "Check for the version of the HelixPlayer packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"HelixPlayer-1.0.5-0.EL4.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
