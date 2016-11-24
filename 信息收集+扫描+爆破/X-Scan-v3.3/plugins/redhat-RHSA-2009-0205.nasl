
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35433);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-0205: dovecot");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0205");
 script_set_attribute(attribute: "description", value: '
  An updated dovecot package that corrects two security flaws and various
  bugs
  is now available for Red Hat Enterprise Linux 5.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Dovecot is an IMAP server for Linux and UNIX-like systems, primarily
  written with security in mind.

  A flaw was found in Dovecot\'s ACL plug-in. The ACL plug-in treated negative
  access rights as positive rights, which could allow an attacker to bypass
  intended access restrictions. (CVE-2008-4577)

  A password disclosure flaw was found with Dovecot\'s configuration file. If
  a system had the "ssl_key_password" option defined, any local user could
  view the SSL key password. (CVE-2008-4870)

  Note: This flaw did not allow the attacker to acquire the contents of the
  SSL key. The password has no value without the key file which arbitrary
  users should not have read access to.

  To better protect even this value, however, the dovecot.conf file now
  supports the "!include_try" directive. The ssl_key_password option should
  be moved from dovecot.conf to a new file owned by, and only readable and
  writable by, root (ie 0600). This file should be referenced from
  dovecot.conf by setting the "!include_try [/path/to/password/file]" option.

  Additionally, this update addresses the following bugs:

  * the dovecot init script -- /etc/rc.d/init.d/dovecot -- did not check if
  the dovecot binary or configuration files existed. It also used the wrong
  pid file for checking the dovecot service\'s status. This update includes a
  new init script that corrects these errors.

  * the %files section of the dovecot spec file did not include "%dir
  %{ssldir}/private". As a consequence, the /etc/pki/private/ directory was
  not owned by dovecot. (Note: files inside /etc/pki/private/ were and are
  owned by dovecot.) With this update, the missing line has been added to the
  spec file, and the noted directory is now owned by dovecot.

  * in some previously released versions of dovecot, the authentication
  process accepted (and passed along un-escaped) passwords containing
  characters that had special meaning to dovecot\'s internal protocols. This
  updated release prevents such passwords from being passed back, instead
  returning the error, "Attempted login with password having illegal chars".

  Note: dovecot versions previously shipped with Red Hat Enterprise Linux 5
  did not allow this behavior. This update addresses the issue above but said
  issue was only present in versions of dovecot not previously included with
  Red Hat Enterprise Linux 5.

  Users of dovecot are advised to upgrade to this updated package, which
  addresses these vulnerabilities and resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0205.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-4577", "CVE-2008-4870");
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

if ( rpm_check( reference:"dovecot-1.0.7-7.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
