
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15943);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-537: openmotif");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-537");
 script_set_attribute(attribute: "description", value: '
  Updated openmotif packages that fix flaws in the Xpm image library are now
  available.

  OpenMotif provides libraries which implement the Motif industry standard
  graphical user interface.

  During a source code audit, Chris Evans and others discovered several stack
  overflow flaws and an integer overflow flaw in the libXpm library used to
  decode XPM (X PixMap) images. A vulnerable version of this library was
  found within OpenMotif. An attacker could create a carefully crafted
  XPM file which would cause an application to crash or potentially execute
  arbitrary code if opened by a victim. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the names
  CAN-2004-0687, CAN-2004-0688, and CAN-2004-0914 to these issues.

  Users of OpenMotif are advised to upgrade to these erratum packages, which
  contain backported security patches to the embedded libXpm library.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-537.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0687", "CVE-2004-0688", "CVE-2004-0914");
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

if ( rpm_check( reference:"openmotif-2.1.30-13.21AS.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.1.30-13.21AS.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-2.2.3-4.RHEL3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.2.3-4.RHEL3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif21-2.1.30-9.RHEL3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
