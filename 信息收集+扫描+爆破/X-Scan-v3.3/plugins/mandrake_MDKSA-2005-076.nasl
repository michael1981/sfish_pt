
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18106);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:076: xli");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:076 (xli).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities have been found in the xli image viewer.
Tavis Ormandy of the Gentoo Linux Security Audit Team discovered a flaw
in the handling of compressed images where shell meta-characters are
not properly escaped (CVE-2005-0638). It was also found that
insufficient validation of image properties could potentially result
in buffer management errors (CVE-2005-0639).
The updated packages have been patched to correct these problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:076");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0638", "CVE-2005-0639");
script_summary(english: "Check for the version of the xli package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xli-1.17.0-8.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xli-1.17.0-8.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xli-", release:"MDK10.1")
 || rpm_exists(rpm:"xli-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-0638", value:TRUE);
 set_kb_item(name:"CVE-2005-0639", value:TRUE);
}
exit(0, "Host is not affected");
