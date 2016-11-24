
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18253);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-412: openmotif");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-412");
 script_set_attribute(attribute: "description", value: '
  Updated openmotif packages that fix a flaw in the Xpm image library are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  OpenMotif provides libraries which implement the Motif industry standard
  graphical user interface.

  An integer overflow flaw was found in libXpm, which is used to decode XPM
  (X PixMap) images. A vulnerable version of this library was
  found within OpenMotif. An attacker could create a carefully crafted XPM
  file which would cause an application to crash or potentially execute
  arbitrary code if opened by a victim. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0605 to
  this issue.

  Users of OpenMotif are advised to upgrade to these erratum packages, which
  contains a backported security patch to the embedded libXpm library.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-412.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0605");
script_summary(english: "Check for the version of the openmotif packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openmotif-2.1.30-13.21AS.5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.1.30-13.21AS.5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-2.2.3-5.RHEL3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.2.3-5.RHEL3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif21-2.1.30-9.RHEL3.6", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-2.2.3-9.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.2.3-9.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif21-2.1.30-11.RHEL4.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
