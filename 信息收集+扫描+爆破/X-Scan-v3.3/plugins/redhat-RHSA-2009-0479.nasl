
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38768);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-0479: perl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0479");
 script_set_attribute(attribute: "description", value: '
  An updated perl-DBD-Pg package that fixes two security issues is now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Perl DBI is a database access Application Programming Interface (API) for
  the Perl language. perl-DBD-Pg allows Perl applications to access
  PostgreSQL database servers.

  A heap-based buffer overflow flaw was discovered in the pg_getline function
  implementation. If the pg_getline or getline functions read large,
  untrusted records from a database, it could cause an application using
  these functions to crash or, possibly, execute arbitrary code.
  (CVE-2009-0663)

  Note: After installing this update, pg_getline may return more data than
  specified by its second argument, as this argument will be ignored. This is
  consistent with current upstream behavior. Previously, the length limit
  (the second argument) was not enforced, allowing a buffer overflow.

  A memory leak flaw was found in the function performing the de-quoting of
  BYTEA type values acquired from a database. An attacker able to cause an
  application using perl-DBD-Pg to perform a large number of SQL queries
  returning BYTEA records, could cause the application to use excessive
  amounts of memory or, possibly, crash. (CVE-2009-1341)

  All users of perl-DBD-Pg are advised to upgrade to this updated package,
  which contains backported patches to fix these issues. Applications using
  perl-DBD-Pg must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0479.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0663", "CVE-2009-1341");
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

if ( rpm_check( reference:"perl-DBD-Pg-1.49-2.el5_3.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
