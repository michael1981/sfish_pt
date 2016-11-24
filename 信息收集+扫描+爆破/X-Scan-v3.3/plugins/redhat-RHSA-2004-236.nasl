
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12502);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2004-236: krb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-236");
 script_set_attribute(attribute: "description", value: '
  Updated Kerberos 5 (krb5) packages which correct buffer overflows in the
  krb5_aname_to_localname function are now available.

  Kerberos is a network authentication system.

  Bugs have been fixed in the krb5_aname_to_localname library function.
  Specifically, buffer overflows were possible for all Kerberos versions up
  to and including 1.3.3. The krb5_aname_to_localname function translates a
  Kerberos principal name to a local account name, typically a UNIX username.
  This function is frequently used when performing authorization checks.

  If configured with mappings from particular Kerberos principals to
  particular UNIX user names, certain functions called by
  krb5_aname_to_localname will not properly check the lengths of buffers
  used to store portions of the principal name. If configured to map
  principals to user names using rules, krb5_aname_to_localname would
  consistently write one byte past the end of a buffer allocated from the
  heap. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-0523 to this issue.

  Only configurations which enable the explicit mapping or rules-based
  mapping functionality of krb5_aname_to_localname() are vulnerable.
  These configurations are not the default.

  Users of Kerberos are advised to upgrade to these erratum packages which
  contain backported security patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-236.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0523");
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

if ( rpm_check( reference:"krb5-devel-1.2.2-27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.2-27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.2-27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.2-27", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.7-24", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-24", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.7-24", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.7-24", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
