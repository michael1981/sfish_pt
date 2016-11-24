
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15534);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-569: mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-569");
 script_set_attribute(attribute: "description", value: '
  Updated mysql packages that fix various temporary file security issues,
  as well as a number of bugs, are now available.

  MySQL is a multi-user, multi-threaded SQL database server.

  This update fixes a number of small bugs, including some potential
  security problems associated with careless handling of temporary files.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the names CAN-2004-0381, CAN-2004-0388, and CAN-2004-0457 to these
  issues.

  A number of additional security issues that affect mysql have been
  corrected in the source package. These include CAN-2004-0835,
  CAN-2004-0836, CAN-2004-0837, and CAN-2004-0957. Red Hat Enterprise Linux
  3 does not ship with the mysql-server package and is therefore not affected
  by these issues.

  This update also allows 32-bit and 64-bit libraries to be installed
  concurrently on the same system.

  All users of mysql should upgrade to these updated packages, which resolve
  these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-569.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0381", "CVE-2004-0388", "CVE-2004-0457");
script_summary(english: "Check for the version of the mysql packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mysql-3.23.58-2.3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-3.23.58-2.3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.58-2.3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
