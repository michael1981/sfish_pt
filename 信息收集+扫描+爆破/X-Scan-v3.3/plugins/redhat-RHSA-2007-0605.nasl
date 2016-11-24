
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25624);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0605: HelixPlayer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0605");
 script_set_attribute(attribute: "description", value: '
  An updated HelixPlayer package that fixes a buffer overflow flaw is now
  available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  HelixPlayer is a media player.

  A buffer overflow flaw was found in the way HelixPlayer processed
  Synchronized Multimedia Integration Language (SMIL) files. It was possible
  for a malformed SMIL file to execute arbitrary code with the permissions of
  the user running HelixPlayer. (CVE-2007-3410)

  All users of HelixPlayer are advised to upgrade to this updated package,
  which contains a backported patch and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0605.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3410");
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

if ( rpm_check( reference:"HelixPlayer-1.0.6-0.EL4.2.0.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
