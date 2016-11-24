
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25477);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0430: openldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0430");
 script_set_attribute(attribute: "description", value: '
  A updated openldap packages that fix a security flaw and a memory leak bug
  are now available for Red Hat Enterprise Linux 3.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
  Protocol) applications, libraries and development tools.

  A flaw was found in the way OpenLDAP handled selfwrite access. Users with
  selfwrite access were able to modify the distinguished name of any user.
  Users with selfwrite access should only be able to modify their own
  distinguished name. (CVE-2006-4600)

  A memory leak bug was found in OpenLDAP\'s ldap_start_tls_s() function. An
  application using this function could result in an Out Of Memory (OOM)
  condition, crashing the application.

  All users are advised to upgrade to this updated openldap package,
  which contains a backported fix and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:A/AC:M/Au:S/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0430.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4600");
script_summary(english: "Check for the version of the openldap packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openldap-2.0.27-23", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-clients-2.0.27-23", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-devel-2.0.27-23", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openldap-servers-2.0.27-23", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
