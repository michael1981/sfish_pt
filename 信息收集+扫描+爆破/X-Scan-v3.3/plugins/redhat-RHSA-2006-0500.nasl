
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22068);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0500: freetype");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0500");
 script_set_attribute(attribute: "description", value: '
  Updated freetype packages that fix several security flaws are now available
  for Red Hat Enterprise Linux.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  FreeType is a free, high-quality, and portable font engine.

  Chris Evans discovered several integer underflow and overflow flaws in the
  FreeType font engine. If a user loads a carefully crafted font file with a
  program linked against FreeType, it could cause the application to crash or
  execute arbitrary code as the user. While it is uncommon for a user to
  explicitly load a font file, there are several application file formats
  which contain embedded fonts that are parsed by FreeType. (CVE-2006-0747,
  CVE-2006-1861, CVE-2006-3467)

  A NULL pointer dereference flaw was found in the FreeType font engine. An
  application linked against FreeType can crash upon loading a malformed font
  file. (CVE-2006-2661)

  Users of FreeType should upgrade to these updated packages, which contain
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0500.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-0747", "CVE-2006-1861", "CVE-2006-2661", "CVE-2006-3467");
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

if ( rpm_check( reference:"freetype-2.0.3-8.rhel2_1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-devel-2.0.3-8.rhel2_1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-utils-2.0.3-8.rhel2_1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-2.1.4-4.0.rhel3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-devel-2.1.4-4.0.rhel3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-2.1.9-1.rhel4.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-demos-2.1.9-1.rhel4.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-devel-2.1.9-1.rhel4.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-utils-2.1.9-1.rhel4.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
