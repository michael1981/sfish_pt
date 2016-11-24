
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-6279
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39541);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-6279: pam_krb5");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-6279 (pam_krb5)");
 script_set_attribute(attribute: "description", value: "This is pam_krb5, a pluggable authentication module that can be used with
Linux-PAM and Kerberos 5. This module supports password checking, ticket
creation, and optional TGT verification and conversion to Kerberos IV tickets.
The included pam_krb5afs module also gets AFS tokens if so configured.

-
Update Information:

This updates the pam_krb5 package from version 2.3.2 to 2.3.5, fixing
CVE-2009-1384: in certain configurations, the password prompt could vary
depending on whether or not the user account was known to the system or the KDC
.
It also fixes a bug which prevented password change attempts from working if th
e
KDC denied requests for password-changing credentials with settings which would
be used for login credentials, and makes the '-n' option for the 'afs5log'
command work as advertised.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3825", "CVE-2009-1384");
script_summary(english: "Check for the version of the pam_krb5 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"pam_krb5-2.3.5-1.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
