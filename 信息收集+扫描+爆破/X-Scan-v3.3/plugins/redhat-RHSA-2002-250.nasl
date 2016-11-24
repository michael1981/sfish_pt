
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12331);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2002-250: krb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-250");
 script_set_attribute(attribute: "description", value: '
  A remotely exploitable stack buffer overflow has been found in the Kerberos
  v4 compatibility administration daemon distributed with the Red Hat Linux
  krb5 packages.

  [Updated 09 Jan 2003]
  Added fixed packages for the Itanium (IA64) architecture.

  Kerberos is a network authentication system.

  A stack buffer overflow has been found in the implementation of the
  Kerberos v4 compatibility administration daemon (kadmind4), which is part
  of the MIT krb5 distribution. This vulnerability is present in version
  1.2.6 and earlier of the MIT krb5 distribution and can be exploited to gain
  unauthorized root access to a KDC host. The attacker does not need to
  authenticate to the daemon to successfully perform this attack.

  kadmind4 is included in the Kerberos packages in Red Hat Linux Advanced
  Server but is not enabled or used by default.

  All users of Kerberos are advised to upgrade to these errata packages which
  contain a backported patch and are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-250.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1235");
script_summary(english: "Check for the version of the krb packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"krb5-devel-1.2.2-15", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-15", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-15", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-15", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
