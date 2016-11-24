
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36566);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:209-1: pam_krb5");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:209-1 (pam_krb5).");
 script_set_attribute(attribute: "description", value: "St?phane Bertin discovered a flaw in the pam_krb5 existing_ticket
configuration option where, if enabled and using an existing credential
cache, it was possible for a local user to gain elevated privileges
by using a different, local user's credential cache (CVE-2008-3825).
The updated packages have been patched to prevent this issue.
Update:
An updated package for Mandriva Linux 2009.0 is now available.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:209-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-3825");
script_summary(english: "Check for the version of the pam_krb5 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pam_krb5-2.3.1-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"pam_krb5-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-3825", value:TRUE);
}
exit(0, "Host is not affected");
