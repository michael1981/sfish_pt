
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22071);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0598: gimp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0598");
 script_set_attribute(attribute: "description", value: '
  Updated gimp packages that fix a security issue are now available for Red
  Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The GIMP (GNU Image Manipulation Program) is an image composition and
  editing program.

  Henning Makholm discovered a buffer overflow bug in The GIMP XCF file
  loader. An attacker could create a carefully crafted image that could
  execute arbitrary code if opened by a victim. (CVE-2006-3404)

  Please note that this issue did not affect the gimp packages in Red Hat
  Enterprise Linux 2.1, or 3.

  Users of The GIMP should update to these erratum packages which contain a
  backported fix to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0598.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-3404");
script_summary(english: "Check for the version of the gimp packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gimp-2.0.5-6", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gimp-devel-2.0.5-6", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
