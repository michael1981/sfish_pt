
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35178);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-1016: enscript");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-1016");
 script_set_attribute(attribute: "description", value: '
  An updated enscript packages that fixes several security issues is now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  GNU enscript converts ASCII files to PostScript(R) language files and
  spools the generated output to a specified printer or saves it to a file.
  Enscript can be extended to handle different output media and includes
  options for customizing printouts.

  Two buffer overflow flaws were found in GNU enscript. An attacker could
  craft an ASCII file in such a way that it could execute arbitrary commands
  if the file was opened with enscript with the "special escapes" option (-e
  or --escapes) enabled. (CVE-2008-3863, CVE-2008-4306)

  All users of enscript should upgrade to these updated packages, which
  contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-1016.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-3863", "CVE-2008-4306");
script_summary(english: "Check for the version of the enscript packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"enscript-1.6.4-4.1.1.el5_2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
