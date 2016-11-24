
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25066);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2007-0150: freetype");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0150");
 script_set_attribute(attribute: "description", value: '
  Updated freetype packages that fix a security flaw are now available for Red
  Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  FreeType is a free, high-quality, portable font engine.

  An integer overflow flaw was found in the way the FreeType font engine
  processed BDF font files. If a user loaded a carefully crafted font file
  with a program linked against FreeType, it could cause the application to
  crash or execute arbitrary code. While it is uncommon for a user to
  explicitly load a font file, there are several application file formats
  which contain embedded fonts that are parsed by FreeType. (CVE-2007-1351)

  This flaw did not affect the version of FreeType shipped in Red Hat
  Enterprise Linux 2.1.

  Users of FreeType should upgrade to these updated packages, which contain
  a backported patch to correct this issue.

  Red Hat would like to thank iDefense for reporting this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0150.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1351");
script_summary(english: "Check for the version of the freetype packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"freetype-2.2.1-17.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-demos-2.2.1-17.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-devel-2.2.1-17.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-2.1.4-6.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-devel-2.1.4-6.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-2.1.9-5.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-demos-2.1.9-5.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-devel-2.1.9-5.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-utils-2.1.9-5.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
