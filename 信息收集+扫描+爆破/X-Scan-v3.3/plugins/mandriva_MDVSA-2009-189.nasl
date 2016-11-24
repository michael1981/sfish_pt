
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40464);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:189: apache-mod_auth_mysql");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:189 (apache-mod_auth_mysql).");
 script_set_attribute(attribute: "description", value: "A vulnerability has been found and corrected in mod_auth_mysql:
SQL injection vulnerability in mod_auth_mysql.c in the mod-auth-mysql
(aka libapache2-mod-auth-mysql) module for the Apache HTTP Server
2.x allows remote attackers to execute arbitrary SQL commands via
multibyte character encodings for unspecified input (CVE-2008-2384).
This update provides fixes for this vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:189");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-2384");
script_summary(english: "Check for the version of the apache-mod_auth_mysql package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apache-mod_auth_mysql-3.0.0-15.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_auth_mysql-3.0.0-17.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"apache-mod_auth_mysql-", release:"MDK2008.1")
 || rpm_exists(rpm:"apache-mod_auth_mysql-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-2384", value:TRUE);
}
exit(0, "Host is not affected");
