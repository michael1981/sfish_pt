
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25896);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:164: tetex");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:164 (tetex).");
 script_set_attribute(attribute: "description", value: "Maurycy Prodeus found an integer overflow vulnerability in the way
various PDF viewers processed PDF files. An attacker could create
a malicious PDF file that could cause tetex to crash and possibly
execute arbitrary code open a user opening the file.
In addition, tetex contains an embedded copy of the GD library which
suffers from a number of bugs which potentially lead to denial of
service and possibly other issues.
Integer overflow in gdImageCreateTrueColor function in the GD Graphics
Library (libgd) before 2.0.35 allows user-assisted remote attackers
to have unspecified remote attack vectors and impact. (CVE-2007-3472)
The gdImageCreateXbm function in the GD Graphics Library (libgd)
before 2.0.35 allows user-assisted remote attackers to cause a denial
of service (crash) via unspecified vectors involving a gdImageCreate
failure. (CVE-2007-3473)
Multiple unspecified vulnerabilities in the GIF reader in the
GD Graphics Library (libgd) before 2.0.35 allow user-assisted
remote attackers to have unspecified attack vectors and
impact. (CVE-2007-3474)
The GD Graphics Library (libgd) before 2.0.35 allows user-assisted
remote attackers to cause a denial of service (crash) via a GIF image
that has no global color map. (CVE-2007-3475)
Array index error in gd_gif_in.c in the GD Graphics Library (libgd)
before 2.0.35 allows user-assisted remote attackers to cause
a denial of service (crash and heap corruption) via large color
index values in crafted image data, which results in a segmentation
fault. (CVE-2007-3476)
The (a) imagearc and (b) imagefilledarc functions in GD Graphics
Library (libgd) before 2.0.35 allows attackers to cause a denial
of service (CPU consumption) via a large (1) start or (2) end angle
degree value. (CVE-2007-3477)
Race condition in gdImageStringFTEx (gdft_draw_bitmap) in gdft.c in the
GD Graphics Library (libgd) before 2.0.35 allows user-assisted remote
attackers to cause a denial of service (crash) via unspecified vectors,
possibly involving truetype font (TTF) support. (CVE-2007-3478)
Updated packages have been patched to prevent these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:164");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-3387", "CVE-2007-3472", "CVE-2007-3473", "CVE-2007-3474", "CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3478");
script_summary(english: "Check for the version of the tetex package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"jadetex-3.12-116.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-3.0-18.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-3.0-18.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-context-3.0-18.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-devel-3.0-18.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-3.0-18.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-3.0-18.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvipdfm-3.0-18.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-3.0-18.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-3.0-18.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-mfwin-3.0-18.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-texi2html-3.0-18.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-3.0-18.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xmltex-1.9-64.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"jadetex-3.12-129.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-context-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-devel-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvipdfm-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-mfwin-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-texi2html-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-usrlocal-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-3.0-31.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xmltex-1.9-77.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"tetex-", release:"MDK2007.0")
 || rpm_exists(rpm:"tetex-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-3387", value:TRUE);
 set_kb_item(name:"CVE-2007-3472", value:TRUE);
 set_kb_item(name:"CVE-2007-3473", value:TRUE);
 set_kb_item(name:"CVE-2007-3474", value:TRUE);
 set_kb_item(name:"CVE-2007-3475", value:TRUE);
 set_kb_item(name:"CVE-2007-3476", value:TRUE);
 set_kb_item(name:"CVE-2007-3477", value:TRUE);
 set_kb_item(name:"CVE-2007-3478", value:TRUE);
}
exit(0, "Host is not affected");
