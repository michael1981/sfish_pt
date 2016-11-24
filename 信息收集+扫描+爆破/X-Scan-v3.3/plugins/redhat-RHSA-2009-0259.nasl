
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35653);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-0259: mod_auth_mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0259");
 script_set_attribute(attribute: "description", value: '
  An updated mod_auth_mysql package to correct a security issue is now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The mod_auth_mysql package includes an extension module for the Apache HTTP
  Server which can be used to implement web user authentication against a
  MySQL database.

  A flaw was found in the way mod_auth_mysql escaped certain
  multibyte-encoded strings. If mod_auth_mysql was configured to use a
  multibyte character set that allowed a backslash \'\\\' as part of the
  character encodings, a remote attacker could inject arbitrary SQL commands
  into a login request. (CVE-2008-2384)

  Note: This flaw only affected non-default installations where
  AuthMySQLCharacterSet is configured to use one of the affected multibyte
  character sets. Installations that did not use the AuthMySQLCharacterSet
  configuration option were not vulnerable to this flaw.

  All mod_auth_mysql users are advised to upgrade to the updated package,
  which contains a backported patch to resolve this issue. After installing
  the update, the httpd daemon must be restarted for the fix to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0259.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2384");
script_summary(english: "Check for the version of the mod_auth_mysql packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mod_auth_mysql-3.0.0-3.2.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
