
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42456);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1572: ");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1572");
 script_set_attribute(attribute: "description", value: '
  An updated 4Suite package that fixes one security issue is now available
  for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The 4Suite package contains XML-related tools and libraries for Python,
  including 4DOM, 4XSLT, 4XPath, 4RDF, and 4XPointer.

  A buffer over-read flaw was found in the way 4Suite\'s XML parser handles
  malformed UTF-8 sequences when processing XML files. A specially-crafted
  XML file could cause applications using the 4Suite library to crash while
  parsing the file. (CVE-2009-3720)

  Note: In Red Hat Enterprise Linux 3, this flaw only affects a non-default
  configuration of the 4Suite package: configurations where the beta version
  of the cDomlette module is enabled.

  All 4Suite users should upgrade to this updated package, which contains a
  backported patch to correct this issue. After installing the updated
  package, applications using the 4Suite XML-related tools and libraries must
  be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1572.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-3720");
script_summary(english: "Check for the version of the  packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"4Suite-0.11.1-15", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"4Suite-1.0-3.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"4Suite-1.0-3.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
