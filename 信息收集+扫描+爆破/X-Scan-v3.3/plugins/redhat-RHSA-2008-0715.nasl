
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33583);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0715: nss_ldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0715");
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

  A race condition was discovered in nss_ldap, which affected certain
  applications that make LDAP connections, such as Dovecot. This could cause
  nss_ldap to answer a request for information about one user with the
  information about a different user. (CVE-2007-5794)

  As well, this updated package fixes the following bugs:

  * in certain situations, on Itanium(R) architectures, when an application
  performed an LDAP lookup for a highly populated group, for example,
  containing more than 150 members, the application crashed, or may have
  caused a segmentation fault. As well, this issue may have caused commands,
  such as "ls", to return a "ber_free_buf: Assertion" error.

  * when an application enumerated members of a netgroup, the nss_ldap
  module returned a successful status result and the netgroup name, even
  when the netgroup did not exist. This behavior was not consistent with
  other modules. In this updated package, nss_ldap no longer returns a
  successful status when the netgroup does not exist.

  * in master and slave server environments, with systems that were
  configured to use a read-only directory server, if user log in attempts
  were denied because their passwords had expired, and users attempted to
  immediately change their passwords, the replication server returned an LDAP
  referral, instructing the pam_ldap module to resissue its request to a
  different server; however, the pam_ldap module failed to do so. In these
  situations, an error such as the following occurred:

  LDAP password information update failed: Can\'t contact LDAP server
  Insufficient \'write\' privilege to the \'userPassword\' attribute of entry
  [entry]

  In this updated package, password changes are allowed when binding against
  a slave server, which resolves this issue.

  * when a system used a directory server for naming information, and
  "nss_initgroups_ignoreusers root" was configured in "/etc/ldap.conf",
  dbus-daemon-1 would hang. Running the "service messagebus start" command
  did not start the service, and it did not fail, which would stop the boot
  process if it was not cancelled.

  As well, this updated package upgrades nss_ldap to the version as shipped
  with Red Hat Enterprise Linux 5.

  Users of nss_ldap are advised to upgrade to this updated package, which
  resolves these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0715.html");
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

if ( rpm_check( reference:"nss_ldap-253-5.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
