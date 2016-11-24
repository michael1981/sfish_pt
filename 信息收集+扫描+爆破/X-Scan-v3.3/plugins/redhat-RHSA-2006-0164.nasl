
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20399);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0164: mod_auth_pgsql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0164");
 script_set_attribute(attribute: "description", value: '
  Updated mod_auth_pgsql packages that fix format string security issues are
  now available for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The mod_auth_pgsql package is an httpd module that allows user
  authentication against information stored in a PostgreSQL database.

  Several format string flaws were found in the way mod_auth_pgsql logs
  information. It may be possible for a remote attacker to execute arbitrary
  code as the \'apache\' user if mod_auth_pgsql is used for user
  authentication. The Common Vulnerabilities and Exposures project assigned
  the name CVE-2005-3656 to this issue.

  Please note that this issue only affects servers which have mod_auth_pgsql
  installed and configured to perform user authentication against a
  PostgreSQL database.

  All users of mod_auth_pgsql should upgrade to these updated packages, which
  contain a backported patch to resolve this issue.

  This issue does not affect the mod_auth_pgsql package supplied with Red Hat
  Enterprise Linux 2.1.

  Red Hat would like to thank iDefense for reporting this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0164.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3656");
script_summary(english: "Check for the version of the mod_auth_pgsql packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mod_auth_pgsql-2.0.1-4.ent.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_auth_pgsql-2.0.1-7.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
