
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21181);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0272: openmotif");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0272");
 script_set_attribute(attribute: "description", value: '
  Updated openmotif packages that fix a security issue are now available.

  This update has been rated as having moderate security impact by the Red Hat
  Security Response Team.

  OpenMotif provides libraries which implement the Motif industry standard
  graphical user interface.

  A number of buffer overflow flaws were discovered in OpenMotif\'s libUil
  library. It is possible for an attacker to execute arbitrary code as a
  victim who has been tricked into executing a program linked against
  OpenMotif, which then loads a malicious User Interface Language (UIL) file.
  (CVE-2005-3964)

  Users of OpenMotif are advised to upgrade to these erratum packages, which
  contain a backported security patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0272.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3964");
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

if ( rpm_check( reference:"openmotif-2.1.30-13.21AS.6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.1.30-13.21AS.6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-2.2.3-5.RHEL3.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.2.3-5.RHEL3.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif21-2.1.30-9.RHEL3.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-2.2.3-10.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.2.3-10.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openmotif21-2.1.30-11.RHEL4.5", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
