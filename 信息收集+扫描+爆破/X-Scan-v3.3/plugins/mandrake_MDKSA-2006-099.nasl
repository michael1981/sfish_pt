
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21715);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:099-1: freetype2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:099-1 (freetype2).");
 script_set_attribute(attribute: "description", value: "Integer underflow in Freetype before 2.2 allows remote attackers to cause
a denial of service (crash) via a font file with an odd number of blue
values, which causes the underflow when decrementing by 2 in a context
that assumes an even number of values. (CVE-2006-0747)
Multiple integer overflows in FreeType before 2.2 allow remote attackers to
cause a denial of service (crash) and possibly execute arbitrary code via
attack vectors related to (1) bdf/bdflib.c, (2) sfnt/ttcmap.c,
(3) cff/cffgload.c, and (4) the read_lwfn function and a crafted LWFN file
in base/ftmac.c. (CVE-2006-1861)
Ftutil.c in Freetype before 2.2 allows remote attackers to cause a denial
of service (crash) via a crafted font file that triggers a null dereference.
(CVE-2006-2661)
In addition, a patch is applied to 2.1.10 in Mandriva 2006 to fix a serious
bug in ttkern.c that caused some programs to go into an infinite loop when
dealing with fonts that don't have a properly sorted kerning sub-table.
This patch is not applicable to the earlier Mandriva releases.
Update:
The previous update introduced some issues with other applications and
libraries linked to libfreetype, that were missed in testing for the
vulnerabilty issues. The new packages correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:099-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-0747", "CVE-2006-1861", "CVE-2006-2661");
script_summary(english: "Check for the version of the freetype2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libfreetype6-2.1.9-6.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-devel-2.1.9-6.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-static-devel-2.1.9-6.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-2.1.10-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-devel-2.1.10-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-static-devel-2.1.10-9.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"freetype2-", release:"MDK10.2")
 || rpm_exists(rpm:"freetype2-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0747", value:TRUE);
 set_kb_item(name:"CVE-2006-1861", value:TRUE);
 set_kb_item(name:"CVE-2006-2661", value:TRUE);
}
exit(0, "Host is not affected");
