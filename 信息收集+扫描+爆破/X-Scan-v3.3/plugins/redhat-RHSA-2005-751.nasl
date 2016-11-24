
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20044);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-751: nss_ldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-751");
 script_set_attribute(attribute: "description", value: '
  Updated openldap and nss_ldap packages that correct a potential password
  disclosure issue are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
  Protocol) applications and development tools.

  The nss_ldap module is an extension for use with GNU libc which allows
  applications to, without internal modification, consult a directory service
  using LDAP to supplement information that would be read from local files
  such as /etc/passwd, /etc/group, and /etc/shadow.

  A bug was found in the way OpenLDAP, nss_ldap, and pam_ldap refer LDAP
  servers. If a client connection is referred to a different server, it is
  possible that the referred connection will not be encrypted even if the
  client has "ssl start_tls" in its ldap.conf file. The Common
  Vulnerabilities and Exposures project has assigned the name CAN-2005-2069
  to this issue.

  A bug was also found in the way certain OpenLDAP authentication schemes
  store hashed passwords. A remote attacker could re-use a hashed password to
  gain access to unauthorized resources. The Common Vulnerabilities and
  Exposures project has assigned the name CAN-2004-0823 to this issue.

  All users of OpenLDAP and nss_ldap are advised to upgrade to these updated
  packages, which contain backported fixes that resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-751.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0823", "CVE-2005-2069");
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

if ( rpm_check( reference:"nss_ldap-189-13", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-2.0.27-4.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-clients-2.0.27-4.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-devel-2.0.27-4.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-servers-2.0.27-4.9", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-207-17", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-2.0.27-20", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-clients-2.0.27-20", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-devel-2.0.27-20", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-servers-2.0.27-20", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
