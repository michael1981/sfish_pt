
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17269);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-271: HelixPlayer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-271");
 script_set_attribute(attribute: "description", value: '
  An updated HelixPlayer package that fixes two buffer overflow issues is now
  available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  HelixPlayer is a media player.

  A stack based buffer overflow bug was found in HelixPlayer\'s Synchronized
  Multimedia Integration Language (SMIL) file processor. An attacker could
  create a specially crafted SMIL file which would execute arbitrary code
  when opened by a user. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0455 to this issue.

  A buffer overflow bug was found in the way HelixPlayer decodes WAV files.
  An attacker could create a specially crafted WAV file which could execute
  arbitrary code when opened by a user. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0611 to
  this issue.

  All users of HelixPlayer are advised to upgrade to this updated package,
  which contains HelixPlayer 1.0.3 which is not vulnerable to these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-271.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0455", "CVE-2005-0611");
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

if ( rpm_check( reference:"HelixPlayer-1.0.3-1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
