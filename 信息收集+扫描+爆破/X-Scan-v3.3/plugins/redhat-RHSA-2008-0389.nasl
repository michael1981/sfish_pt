
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32426);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0389: nss_ldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0389");
 script_set_attribute(attribute: "description", value: '
  An updated nss_ldap package that fixes a security issue and several bugs is
  now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The nss_ldap package contains the nss_ldap and pam_ldap modules. The
  nss_ldap module is a plug-in which allows applications to retrieve
  information about users and groups from a directory server. The pam_ldap
  module allows PAM-aware applications to use a directory server to verify
  user passwords.

  A race condition was discovered in nss_ldap which affected certain
  applications which make LDAP connections, such as Dovecot. This could cause
  nss_ldap to answer a request for information about one user with
  information about a different user. (CVE-2007-5794)

  In addition, these updated packages fix the following bugs:

  * a build error prevented the nss_ldap module from being able to use DNS to
  discover the location of a directory server. For example, when the
  /etc/nsswitch.conf configuration file was configured to use "ldap", but no
  "host" or "uri" option was configured in the /etc/ldap.conf configuration
  file, no directory server was contacted, and no results were returned.

  * the "port" option in the /etc/ldap.conf configuration file on client
  machines was ignored. For example, if a directory server which you were
  attempting to use was listening on a non-default port (i.e. not ports 389
  or 636), it was only possible to use that directory server by including the
  port number in the "uri" option. In this updated package, the "port" option
  works as expected.

  * pam_ldap failed to change an expired password if it had to follow a
  referral to do so, which could occur, for example, when using a slave
  directory server in a replicated environment. An error such as the
  following occurred after entering a new password: "LDAP password
  information update failed: Can\'t contact LDAP server Insufficient \'write\'
  privilege to the \'userPassword\' attribute"

  This has been resolved in this updated package.

  * when the "pam_password exop_send_old" password-change method was
  configured in the /etc/ldap.conf configuration file, a logic error in the
  pam_ldap module caused client machines to attempt to change a user\'s
  password twice. First, the pam_ldap module attempted to change the password
  using the "exop" request, and then again using an LDAP modify request.

  * on Red Hat Enterprise Linux 5.1, rebuilding nss_ldap-253-5.el5 when the
  krb5-*-1.6.1-17.el5 packages were installed failed due to an error such as
  the following:

  + /builddir/build/SOURCES/dlopen.sh ./nss_ldap-253/nss_ldap.so
  dlopen() of "././nss_ldap-253/nss_ldap.so" failed:
  ./././nss_ldap-253/nss_ldap.so: undefined symbol: request_key
  error: Bad exit status from /var/tmp/rpm-tmp.62652 (%build)

  The missing libraries have been added, which resolves this issue.

  When recursively enumerating the set of members in a given group, the
  module would allocate insufficient space for storing the set of member
  names if the group itself contained other groups, thus corrupting the heap.
  This update includes a backported fix for this bug.

  Users of nss_ldap should upgrade to these updated packages, which contain
  backported patches to correct this issue and fix these bugs.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0389.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5794");
script_summary(english: "Check for the version of the nss_ldap packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"nss_ldap-253-12.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
