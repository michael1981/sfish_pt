
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20877);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:037: mozilla-firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:037 (mozilla-firefox).");
 script_set_attribute(attribute: "description", value: "Mozilla and Mozilla Firefox allow remote attackers to cause a denial of
service (CPU consumption and delayed application startup) via a web
site with a large title, which is recorded in history.dat but not
processed efficiently during startup. (CVE-2005-4134)
The Javascript interpreter (jsinterp.c) in Mozilla and Firefox before
1.5.1 does not properly dereference objects, which allows remote
attackers to cause a denial of service (crash) or execute arbitrary
code via unknown attack vectors related to garbage collection.
(CVE-2006-0292)
The XULDocument.persist function in Mozilla, Firefox before 1.5.0.1,
and SeaMonkey before 1.0 does not validate the attribute name, which
allows remote attackers to execute arbitrary Javascript by injecting
RDF data into the user's localstore.rdf file. (CVE-2006-0296)
Updated packages are patched to address these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:037");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0296");
script_summary(english: "Check for the version of the mozilla-firefox package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libnspr4-1.0.6-16.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnspr4-devel-1.0.6-16.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnss3-1.0.6-16.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnss3-devel-1.0.6-16.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-firefox-1.0.6-16.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-firefox-devel-1.0.6-16.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mozilla-firefox-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-4134", value:TRUE);
 set_kb_item(name:"CVE-2006-0292", value:TRUE);
 set_kb_item(name:"CVE-2006-0296", value:TRUE);
}
exit(0, "Host is not affected");
