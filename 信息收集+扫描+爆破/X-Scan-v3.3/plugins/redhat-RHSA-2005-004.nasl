
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16144);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2005-004: lesstif");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-004");
 script_set_attribute(attribute: "description", value: '
  An updated lesstif package that fixes flaws in the Xpm library is now
  available for Red Hat Enterprise Linux 2.1.

  LessTif provides libraries which implement the Motif industry standard
  graphical user interface.

  During a source code audit, Chris Evans discovered several stack overflow
  flaws and an integer overflow flaw in the libXpm library used to decode XPM
  (X PixMap) images. A vulnerable version of this library was found within
  Lesstif. An attacker could create a carefully crafted XPM file which would
  cause an application to crash or potentially execute arbitrary code if
  opened by a victim. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the names CAN-2004-0687,CAN-2004-0688, and
  CAN-2004-0914 to these issues.

  Users of LessTif are advised to upgrade to this erratum package, which
  contains backported security patches to the embedded libXpm library.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-004.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0687", "CVE-2004-0688", "CVE-2004-0914");
script_summary(english: "Check for the version of the lesstif packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lesstif-0.93.15-4.AS21.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lesstif-devel-0.93.15-4.AS21.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
