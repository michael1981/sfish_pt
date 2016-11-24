
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12383);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-114: mod_auth_any");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-114");
 script_set_attribute(attribute: "description", value: '
  Updated mod_auth_any packages are available for Red Hat Enterprise Linux.
  These updated packages fix vulnerabilities associated with the manner in
  which mod_auth_any escapes shell arguments when calling external programs.

  The Web server module mod_auth_any allows the Apache httpd server to
  call arbitrary external programs to verify user passwords.

  Vulnerabilities have been found in versions of mod_auth_any included in Red
  Hat Enterprise Linux concerning the method by which mod_auth_any escapes
  shell arguments when calling external programs. These vulnerabilities
  allow remote attackers to run arbitrary commands as the user under which
  the Web server is running. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2003-0084 to these
  issues.

  All users are advised to upgrade to these errata packages, which change the
  method by which external programs are invoked and, therefore, make these
  programs invulnerable to these issues.

  Red Hat would like to thank Daniel Jarboe and Maneesh Sahani for bringing
  these issues to our attention.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-114.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0084");
script_summary(english: "Check for the version of the mod_auth_any packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mod_auth_any-1.2.2-2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
