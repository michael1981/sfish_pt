
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12489);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-172: gmc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-172");
 script_set_attribute(attribute: "description", value: '
  Updated mc packages that resolve several buffer overflow vulnerabilities,
  one format string vulnerability and several temporary file creation
  vulnerabilities are now available.

  Midnight Commander (mc) is a visual shell much like a file manager.

  Several buffer overflows, several temporary file creation vulnerabilities,
  and one format string vulnerability have been discovered in Midnight
  Commander. These vulnerabilities were discovered mostly by Andrew V.
  Samoilov and Pavel Roskin. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the names CAN-2004-0226,
  CAN-2004-0231, and CAN-2004-0232 to these issues.

  Users should upgrade to these updated packages, which contain a backported
  patch to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-172.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0226", "CVE-2004-0231", "CVE-2004-0232");
script_summary(english: "Check for the version of the gmc packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gmc-4.5.51-36.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mc-4.5.51-36.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mcserv-4.5.51-36.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
