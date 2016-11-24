
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12385);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2003-121: sendmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-121");
 script_set_attribute(attribute: "description", value: '
  Updated Sendmail packages are available to fix a vulnerability that
  allows local and possibly remote attackers to gain root privileges.

  Sendmail is a widely used Mail Transport Agent (MTA) which is included
  in all Red Hat Enterprise Linux distributions.

  There is a vulnerability in Sendmail versions 8.12.8 and prior. The
  address parser performs insufficient bounds checking in certain conditions
  due to a char to int conversion, making it possible for an attacker to
  take control of the application. Although no exploit currently exists,
  this issue is probably locally exploitable and may be remotely exploitable.

  All users are advised to update to these erratum packages containing a
  backported patch which corrects these vulnerabilities.

  Red Hat would like to thank Michal Zalewski for finding and reporting this
  issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-121.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0161");
script_summary(english: "Check for the version of the sendmail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sendmail-8.11.6-26.72", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.11.6-26.72", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.11.6-26.72", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.11.6-26.72", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
