
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36403);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:055: audacity");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:055 (audacity).");
 script_set_attribute(attribute: "description", value: "A vulnerability has been identified and corrected in audacity:
Stack-based buffer overflow in the String_parse::get_nonspace_quoted
function in lib-src/allegro/strparse.cpp in Audacity 1.2.6 and other
versions before 1.3.6 allows remote attackers to cause a denial of
service (crash) and possibly execute arbitrary code via a .gro file
containing a long string (CVE-2009-0490).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:055");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-0490");
script_summary(english: "Check for the version of the audacity package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"audacity-1.3.3-1.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"audacity-1.3.4-7.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"audacity-1.3.5-3.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"audacity-", release:"MDK2008.0")
 || rpm_exists(rpm:"audacity-", release:"MDK2008.1")
 || rpm_exists(rpm:"audacity-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-0490", value:TRUE);
}
exit(0, "Host is not affected");
