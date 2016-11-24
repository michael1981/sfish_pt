
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38982);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:126: eggdrop");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:126 (eggdrop).");
 script_set_attribute(attribute: "description", value: "mod/server.mod/servmsg.c in Eggheads Eggdrop and Windrop 1.6.19 and
earlier allows remote attackers to cause a denial of service (crash)
via a crafted PRIVMSG that causes an empty string to trigger a negative
string length copy. NOTE: this issue exists because of an incorrect
fix for CVE-2007-2807 (CVE-2009-1789).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:126");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-2807", "CVE-2009-1789");
script_summary(english: "Check for the version of the eggdrop package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"eggdrop-1.6.18-5.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"eggdrop-1.6.19-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"eggdrop-1.6.19-3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"eggdrop-", release:"MDK2008.1")
 || rpm_exists(rpm:"eggdrop-", release:"MDK2009.0")
 || rpm_exists(rpm:"eggdrop-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2007-2807", value:TRUE);
 set_kb_item(name:"CVE-2009-1789", value:TRUE);
}
exit(0, "Host is not affected");
