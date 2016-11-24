
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19284);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-584: zlib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-584");
 script_set_attribute(attribute: "description", value: '
  Updated zlib packages that fix a buffer overflow are now available for Red
  Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Zlib is a general-purpose lossless data compression library that is used
  by many different programs.

  A previous zlib update, RHSA-2005:569 (CAN-2005-2096) fixed a flaw in zlib
  that could allow a carefully crafted compressed stream to crash an
  application. While the original patch corrected the reported overflow,
  Markus Oberhumer discovered additional ways a stream could trigger an
  overflow. An attacker could create a carefully crafted compressed stream
  that would cause an application to crash if the stream is opened by a user.
  As an example, an attacker could create a malicious PNG image file that
  would cause a Web browser or mail viewer to crash if the image is viewed.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) assigned
  the name CAN-2005-1849 to this issue.

  Note that the versions of zlib shipped with Red Hat Enterprise
  Linux 2.1 and 3 are not vulnerable to this issue.

  All users should update to these errata packages that contain a patch
  from Mark Adler that corrects this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-584.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1849");
script_summary(english: "Check for the version of the zlib packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"zlib-1.2.1.2-1.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.1.2-1.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
