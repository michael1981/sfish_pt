
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32423);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2008-0297: dovecot");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0297");
 script_set_attribute(attribute: "description", value: '
  An updated dovecot package that fixes several security issues and various
  bugs is now available for Red Hat Enterprise Linux 5.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Dovecot is an IMAP server for Linux and UNIX-like systems, primarily
  written with security in mind.

  A flaw was discovered in the way Dovecot handled the "mail_extra_groups"
  option. An authenticated attacker with local shell access could leverage
  this flaw to read, modify, or delete other users mail that is stored on
  the mail server. (CVE-2008-1199)

  This issue did not affect the default Red Hat Enterprise Linux 5 Dovecot
  configuration. This update adds two new configuration options --
  "mail_privileged_group" and "mail_access_groups" -- to minimize the usage
  of additional privileges.

  A directory traversal flaw was discovered in Dovecot\'s zlib plug-in. An
  authenticated user could use this flaw to view other compressed mailboxes
  with the permissions of the Dovecot process. (CVE-2007-2231)

  A flaw was found in the Dovecot ACL plug-in. User with only insert
  permissions for a mailbox could use the "COPY" and "APPEND" commands to set
  additional message flags. (CVE-2007-4211)

  A flaw was found in a way Dovecot cached LDAP query results in certain
  configurations. This could possibly allow authenticated users to log in as
  a different user who has the same password. (CVE-2007-6598)

  As well, this updated package fixes the following bugs:

  * configuring "userdb" and "passdb" to use LDAP caused Dovecot to hang. A
  segmentation fault may have occurred. In this updated package, using an
  LDAP backend for "userdb" and "passdb" no longer causes Dovecot to hang.

  * the Dovecot "login_process_size" limit was configured for 32-bit systems.
  On 64-bit systems, when Dovecot was configured to use either IMAP or POP3,
  the log in processes crashed with out-of-memory errors. Errors such as the
  following were logged:

  pop3-login: pop3-login: error while loading shared libraries:
  libsepol.so.1: failed to map segment from shared object: Cannot allocate
  memory

  In this updated package, the "login_process_size" limit is correctly
  configured on 64-bit systems, which resolves this issue.

  Note: this updated package upgrades dovecot to version 1.0.7. For
  further details, refer to the Dovecot changelog:
  http://koji.fedoraproject.org/koji/buildinfo?buildID=23397

  Users of dovecot are advised to upgrade to this updated package, which
  resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0297.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2231", "CVE-2007-4211", "CVE-2007-6598", "CVE-2008-1199");
script_summary(english: "Check for the version of the dovecot packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dovecot-1.0.7-2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
