
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42181);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:282: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:282 (cups).");
 script_set_attribute(attribute: "description", value: "Multiple integer overflows in the JBIG2 decoder in
Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier, and
other products allow remote attackers to cause a denial
of service (crash) via a crafted PDF file, related to (1)
JBIG2Stream::readSymbolDictSeg, (2) JBIG2Stream::readSymbolDictSeg,
and (3) JBIG2Stream::readGenericBitmap. (CVE-2009-0146, CVE-2009-0147)
Integer overflow in the TIFF image decoding routines in CUPS 1.3.9 and
earlier allows remote attackers to cause a denial of service (daemon
crash) and possibly execute arbitrary code via a crafted TIFF image,
which is not properly handled by the (1) _cupsImageReadTIFF function
in the imagetops filter and (2) imagetoraster filter, leading to a
heap-based buffer overflow. (CVE-2009-0163)
Integer overflow in the JBIG2 decoder in Xpdf 3.02pl2 and earlier,
as used in Poppler and other products, when running on Mac OS X,
has unspecified impact, related to g*allocn. (CVE-2009-0165)
The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
and other products allows remote attackers to cause a denial of service
(crash) via a crafted PDF file that triggers a free of uninitialized
memory. (CVE-2009-0166)
Heap-based buffer overflow in Xpdf 3.02pl2 and earlier, CUPS 1.3.9,
and probably other products, allows remote attackers to execute
arbitrary code via a PDF file with crafted JBIG2 symbol dictionary
segments (CVE-2009-0195).
Multiple integer overflows in the pdftops filter in CUPS 1.1.17,
1.1.22, and 1.3.7 allow remote attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via a crafted
PDF file that triggers a heap-based buffer overflow, possibly
related to (1) Decrypt.cxx, (2) FoFiTrueType.cxx, (3) gmem.c,
(4) JBIG2Stream.cxx, and (5) PSOutputDev.cxx in pdftops/. NOTE:
the JBIG2Stream.cxx vector may overlap CVE-2009-1179. (CVE-2009-0791)
The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
Poppler before 0.10.6, and other products allows remote attackers to
cause a denial of service (crash) via a crafted PDF file that triggers
an out-of-bounds read. (CVE-2009-0799)
Multiple input validation flaws in the JBIG2 decoder in Xpdf 3.02pl2
and earlier, CUPS 1.3.9 and earlier, Poppler before 0.10.6, and
other products allow remote attackers to execute arbitrary code via
a crafted PDF file. (CVE-2009-0800)
The ippReadIO function in cups/ipp.c in cupsd in CUPS before 1.3.10
does not properly initialize memory for IPP request packets, which
allows remote attackers to cause a denial of service (NULL pointer
dereference and daemon crash) via a scheduler request with two
consecutive IPP_TAG_UNSUPPORTED tags. (CVE-2009-0949)
Integer overflow in the JBIG2 decoder in Xpdf 3.02pl2 and earlier,
CUPS 1.3.9 and earlier, Poppler before 0.10.6, and other products
allows remote attackers to execute arbitrary code via a crafted PDF
file. (CVE-2009-1179)
The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
Poppler before 0.10.6, and other products allows remote attackers to
execute arbitrary code via a crafted PDF file that triggers a free
of invalid data. (CVE-2009-1180)
The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
Poppler before 0.10.6, and other products allows remote attackers to
cause a denial of service (crash) via a crafted PDF file that triggers
a NULL pointer dereference. (CVE-2009-1181)
Multiple buffer overflows in the JBIG2 MMR decoder in Xpdf 3.02pl2
and earlier, CUPS 1.3.9 and earlier, Poppler before 0.10.6, and
other products allow remote attackers to execute arbitrary code via
a crafted PDF file. (CVE-2009-1182)
The JBIG2 MMR decoder in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and
earlier, Poppler before 0.10.6, and other products allows remote
attackers to cause a denial of service (infinite loop and hang)
via a crafted PDF file. (CVE-2009-1183)
Two integer overflow flaws were found in the CUPS pdftops filter. An
attacker could create a malicious PDF file that would cause pdftops
to crash or, potentially, execute arbitrary code as the lp user if
the file was printed. (CVE-2009-3608, CVE-2009-3609)
This update corrects the problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:282");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0163", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0791", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-0949", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-3608", "CVE-2009-3609");
script_summary(english: "Check for the version of the cups package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"acl-2.2.47-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-1.3.10-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.3.10-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.3.10-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libacl1-2.2.47-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libacl-devel-2.2.47-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcups2-1.3.10-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcups2-devel-1.3.10-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpoppler3-0.8.7-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpoppler-devel-0.8.7-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpoppler-glib3-0.8.7-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpoppler-glib-devel-0.8.7-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpoppler-qt2-0.8.7-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpoppler-qt4-3-0.8.7-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpoppler-qt4-devel-0.8.7-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpoppler-qt-devel-0.8.7-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cups-1.3.10-0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"poppler-0.8.7-2.3mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"cups-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-0146", value:TRUE);
 set_kb_item(name:"CVE-2009-0147", value:TRUE);
 set_kb_item(name:"CVE-2009-0163", value:TRUE);
 set_kb_item(name:"CVE-2009-0165", value:TRUE);
 set_kb_item(name:"CVE-2009-0166", value:TRUE);
 set_kb_item(name:"CVE-2009-0195", value:TRUE);
 set_kb_item(name:"CVE-2009-0791", value:TRUE);
 set_kb_item(name:"CVE-2009-0799", value:TRUE);
 set_kb_item(name:"CVE-2009-0800", value:TRUE);
 set_kb_item(name:"CVE-2009-0949", value:TRUE);
 set_kb_item(name:"CVE-2009-1179", value:TRUE);
 set_kb_item(name:"CVE-2009-1180", value:TRUE);
 set_kb_item(name:"CVE-2009-1181", value:TRUE);
 set_kb_item(name:"CVE-2009-1182", value:TRUE);
 set_kb_item(name:"CVE-2009-1183", value:TRUE);
 set_kb_item(name:"CVE-2009-3608", value:TRUE);
 set_kb_item(name:"CVE-2009-3609", value:TRUE);
}
exit(0, "Host is not affected");
