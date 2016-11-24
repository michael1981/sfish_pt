
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20475);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:009: apache2-mod_auth_pgsql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:009 (apache2-mod_auth_pgsql).");
 script_set_attribute(attribute: "description", value: "iDefense discovered several format string vulnerabilities in the way
that mod_auth_pgsql logs information which could potentially be used
by a remote attacker to execute arbitrary code as the apache user if
mod_auth_pgsql is used for user authentication.
The provided packages have been patched to prevent this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:009");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-3656");
script_summary(english: "Check for the version of the apache2-mod_auth_pgsql package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apache2-mod_auth_pgsql-2.0.50_2.0.2b1-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache2-mod_auth_pgsql-2.0.53_2.0.2b1-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_auth_pgsql-2.0.54_2.0.2b1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"apache2-mod_auth_pgsql-", release:"MDK10.1")
 || rpm_exists(rpm:"apache2-mod_auth_pgsql-", release:"MDK10.2")
 || rpm_exists(rpm:"apache2-mod_auth_pgsql-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3656", value:TRUE);
}
exit(0, "Host is not affected");
