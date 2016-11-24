
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40967);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:231: htmldoc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:231 (htmldoc).");
 script_set_attribute(attribute: "description", value: "A security vulnerability has been identified and fixed in htmldoc:
Buffer overflow in the set_page_size function in util.cxx in HTMLDOC
1.8.27 and earlier allows context-dependent attackers to execute
arbitrary code via a long MEDIA SIZE comment. NOTE: it was later
reported that there were additional vectors in htmllib.cxx and
ps-pdf.cxx using an AFM font file with a long glyph name, but these
vectors do not cross privilege boundaries (CVE-2009-3050).
This update provides a solution to this vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:231");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-3050");
script_summary(english: "Check for the version of the htmldoc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"htmldoc-1.8.27-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"htmldoc-nogui-1.8.27-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"htmldoc-1.8.27-3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"htmldoc-nogui-1.8.27-3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"htmldoc-", release:"MDK2009.0")
 || rpm_exists(rpm:"htmldoc-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-3050", value:TRUE);
}
exit(0, "Host is not affected");
