
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38164);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:095: ghostscript");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:095 (ghostscript).");
 script_set_attribute(attribute: "description", value: "A buffer underflow in Ghostscript's CCITTFax decoding filter allows
remote attackers to cause denial of service and possibly to execute
arbitrary by using a crafted PDF file (CVE-2007-6725).
Buffer overflow in Ghostscript's BaseFont writer module allows
remote attackers to cause a denial of service and possibly to execute
arbitrary code via a crafted Postscript file (CVE-2008-6679).
Multiple interger overflows in Ghostsript's International Color
Consortium Format Library (icclib) allows attackers to cause denial
of service (heap-based buffer overflow and application crash) and
possibly execute arbirary code by using either a PostScript or PDF
file with crafte embedded images (CVE-2009-0583, CVE-2009-0584).
Multiple interger overflows in Ghostsript's International Color
Consortium Format Library (icclib) allows attackers to cause denial
of service (heap-based buffer overflow and application crash) and
possibly execute arbirary code by using either a PostScript or PDF
file with crafte embedded images. Note: this issue exists because of
an incomplete fix for CVE-2009-0583 (CVE-2009-0792).
Heap-based overflow in Ghostscript's JBIG2 decoding library allows
attackers to cause denial of service and possibly to execute arbitrary
code by using a crafted PDF file (CVE-2009-0196).
This update provides fixes for that vulnerabilities.
Update:
gostscript packages from Mandriva Linux 2009.0 distribution are not
affected by CVE-2007-6725.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:095");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-6725", "CVE-2008-6679", "CVE-2009-0196", "CVE-2009-0583", "CVE-2009-0584", "CVE-2009-0792");
script_summary(english: "Check for the version of the ghostscript package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ghostscript-8.61-60.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-common-8.61-60.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-doc-8.61-60.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-dvipdf-8.61-60.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-module-X-8.61-60.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-X-8.61-60.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgs8-8.61-60.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgs8-devel-8.61-60.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libijs1-0.35-60.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libijs1-devel-0.35-60.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-8.63-62.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-common-8.63-62.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-doc-8.63-62.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-dvipdf-8.63-62.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-module-X-8.63-62.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ghostscript-X-8.63-62.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgs8-8.63-62.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgs8-devel-8.63-62.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libijs1-0.35-62.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libijs1-devel-0.35-62.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ghostscript-", release:"MDK2008.1")
 || rpm_exists(rpm:"ghostscript-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2007-6725", value:TRUE);
 set_kb_item(name:"CVE-2008-6679", value:TRUE);
 set_kb_item(name:"CVE-2009-0196", value:TRUE);
 set_kb_item(name:"CVE-2009-0583", value:TRUE);
 set_kb_item(name:"CVE-2009-0584", value:TRUE);
 set_kb_item(name:"CVE-2009-0792", value:TRUE);
}
exit(0, "Host is not affected");
