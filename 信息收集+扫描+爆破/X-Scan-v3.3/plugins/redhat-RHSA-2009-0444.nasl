
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(37605);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-0444: giflib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0444");
 script_set_attribute(attribute: "description", value: '
  Updated giflib packages that fix several security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The giflib packages contain a shared library of functions for loading and
  saving GIF image files. This library is API and ABI compatible with
  libungif, the library that supported uncompressed GIF image files while the
  Unisys LZW patent was in effect.

  Several flaws were discovered in the way giflib decodes GIF images. An
  attacker could create a carefully crafted GIF image that could cause an
  application using giflib to crash or, possibly, execute arbitrary code when
  opened by a victim. (CVE-2005-2974, CVE-2005-3350)

  All users of giflib are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. All running
  applications using giflib must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0444.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2974", "CVE-2005-3350");
script_summary(english: "Check for the version of the giflib packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"giflib-4.1.3-7.1.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"giflib-devel-4.1.3-7.1.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"giflib-utils-4.1.3-7.1.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
