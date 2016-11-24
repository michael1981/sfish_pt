
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41962);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1471: elinks");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1471");
 script_set_attribute(attribute: "description", value: '
  An updated elinks package that fixes two security issues is now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  ELinks is a text-based Web browser. ELinks does not display any images, but
  it does support frames, tables, and most other HTML tags.

  An off-by-one buffer overflow flaw was discovered in the way ELinks handled
  its internal cache of string representations for HTML special entities. A
  remote attacker could use this flaw to create a specially-crafted HTML file
  that would cause ELinks to crash or, possibly, execute arbitrary code when
  rendered. (CVE-2008-7224)

  It was discovered that ELinks tried to load translation files using
  relative paths. A local attacker able to trick a victim into running ELinks
  in a folder containing specially-crafted translation files could use this
  flaw to confuse the victim via incorrect translations, or cause ELinks to
  crash and possibly execute arbitrary code via embedded formatting sequences
  in translated messages. (CVE-2007-2027)

  All ELinks users are advised to upgrade to this updated package, which
  contains backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1471.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2027", "CVE-2008-7224");
script_summary(english: "Check for the version of the elinks packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"elinks-0.11.1-6.el5_4.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"elinks-0.9.2-4.el4_8.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"elinks-0.9.2-4.el4_8.1", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"elinks-0.11.1-6.el5_4.1", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
