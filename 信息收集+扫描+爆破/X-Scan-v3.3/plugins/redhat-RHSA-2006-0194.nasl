
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20856);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0194: gd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0194");
 script_set_attribute(attribute: "description", value: '
  Updated gd packages that fix several buffer overflow flaws are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The gd package contains a graphics library used for the dynamic creation of
  images such as PNG and JPEG.

  Several buffer overflow flaws were found in the way gd allocates memory.
  An attacker could create a carefully crafted image that could execute
  arbitrary code if opened by a victim using a program linked against the gd
  library. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  assigned the name CVE-2004-0941 to these issues.

  Users of gd should upgrade to these updated packages, which contain a
  backported patch and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0194.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0941");
script_summary(english: "Check for the version of the gd packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gd-2.0.28-4.4E.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gd-devel-2.0.28-4.4E.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gd-progs-2.0.28-4.4E.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
