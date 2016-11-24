
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12462);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-053: sysstat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-053");
 script_set_attribute(attribute: "description", value: '
  Updated sysstat packages that fix various bugs and security issues are now
  available.

  Sysstat is a tool for gathering system statistics. Isag is a utility for
  graphically displaying these statistics.

  A bug was found in the Red Hat sysstat package post and trigger scripts,
  which used insecure temporary file names. A local attacker could overwrite
  system files using carefully-crafted symbolic links in the /tmp directory.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-0107 to this issue.

  While fixing this issue, a flaw was discovered in the isag utility, which
  also used insecure temporary file names. A local attacker could overwrite
  files that the user running isag has write access to using
  carefully-crafted symbolic links in the /tmp directory. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0108 to this issue.

  Other issues addressed in this advisory include:

  * iostat -x should return all partitions on the system (up to a maximum of
  1024)

  * sar should handle network device names with more than 8 characters
  properly

  * mpstat should work correctly with more than 7 CPUs as well as generate
  correct statistics when accessing individual CPUs. This issue only
  affected Red Hat Enterprise Linux 2.1

  * The sysstat package was not built with the proper dependencies;
  therefore, it was possible that isag could not be run because the necessary
  tools were not available. Therefore, isag was split off into its own
  subpackage with the required dependencies in place. This issue only
  affects Red Hat Enterprise Linux 2.1.

  Users of sysstat and isag should upgrade to these updated packages, which
  contain patches to correct these issues.

  NOTE: In order to use isag on Red Hat Enterprise Linux 2.1, you must
  install the sysstat-isag package after upgrading.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-053.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0107", "CVE-2004-0108");
script_summary(english: "Check for the version of the sysstat packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sysstat-4.0.1-12", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sysstat-isag-4.0.1-12", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sysstat-4.0.7-4.EL3.2", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
