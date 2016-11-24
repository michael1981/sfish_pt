
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16298);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-069: perl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-069");
 script_set_attribute(attribute: "description", value: '
  An updated perl-DBI package that fixes a temporary file flaw in
  DBI::ProxyServer is now available.

  DBI is a database access Application Programming Interface (API) for
  the Perl programming language.

  The Debian Security Audit Project discovered that the DBI library creates a
  temporary PID file in an insecure manner. A local user could overwrite or
  create files as a different user who happens to run an application which
  uses DBI::ProxyServer. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0077 to this issue.

  Users should update to this erratum package which disables the temporary
  PID file unless configured.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-069.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0077");
script_summary(english: "Check for the version of the perl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"perl-DBI-1.18-3", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-DBI-1.32-9", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
