
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37379);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:106: gnutls");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:106 (gnutls).");
 script_set_attribute(attribute: "description", value: "Flaws discovered in versions prior to 2.2.4 (stable) and 2.3.10
(development) of GnuTLS allow an attacker to cause denial of service
(application crash), and maybe (so far undetermined) execute arbitrary
code.
The updated packages have been patched to fix these flaws.
Note that any applications using this library must be restarted for
the update to take effect.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:106");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-1948", "CVE-2008-1949", "CVE-2008-1950");
script_summary(english: "Check for the version of the gnutls package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gnutls-1.6.1-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls13-1.6.1-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls13-devel-1.6.1-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnutls-2.0.0-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls13-2.0.0-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls-devel-2.0.0-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnutls-2.3.0-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls26-2.3.0-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls-devel-2.3.0-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gnutls-", release:"MDK2007.1")
 || rpm_exists(rpm:"gnutls-", release:"MDK2008.0")
 || rpm_exists(rpm:"gnutls-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-1948", value:TRUE);
 set_kb_item(name:"CVE-2008-1949", value:TRUE);
 set_kb_item(name:"CVE-2008-1950", value:TRUE);
}
exit(0, "Host is not affected");
