
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40707);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2007-0841: realplayer");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0841");
 script_set_attribute(attribute: "description", value: '
  An updated RealPlayer package that fixes a security flaw is now available
  for Red Hat Enterprise Linux 3 Extras, 4 Extras, and 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  RealPlayer is a media player that provides media playback locally and via
  streaming.

  A buffer overflow flaw was found in the way RealPlayer processed
  Synchronized Multimedia Integration Language (SMIL) files. It was possible
  for a malformed SMIL file to execute arbitrary code with the permissions of
  the user running RealPlayer. (CVE-2007-3410)

  All users of RealPlayer are advised to upgrade to this updated package
  containing RealPlayer version 10.0.9 which is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0841.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2263", "CVE-2007-2264", "CVE-2007-3410", "CVE-2007-5081");
script_summary(english: "Check for the version of the realplayer packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"realplayer-10.0.9-0.rhel3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"RealPlayer-10.0.9-2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
