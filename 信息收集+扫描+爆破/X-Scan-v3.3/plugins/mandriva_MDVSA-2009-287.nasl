
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42215);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:287: xpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:287 (xpdf).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in xpdf:
Integer overflow in the SplashBitmap::SplashBitmap function in Xpdf 3.x
before 3.02pl4 and Poppler before 0.12.1 might allow remote attackers
to execute arbitrary code via a crafted PDF document that triggers a
heap-based buffer overflow. NOTE: some of these details are obtained
from third party information. NOTE: this issue reportedly exists
because of an incomplete fix for CVE-2009-1188 (CVE-2009-3603).
The Splash::drawImage function in Splash.cc in Xpdf 2.x and 3.x
before 3.02pl4, and Poppler 0.x, as used in GPdf and kdegraphics KPDF,
does not properly allocate memory, which allows remote attackers to
cause a denial of service (application crash) or possibly execute
arbitrary code via a crafted PDF document that triggers a NULL pointer
dereference or a heap-based buffer overflow (CVE-2009-3604).
Integer overflow in the PSOutputDev::doImageL1Sep function in Xpdf
before 3.02pl4, and Poppler 0.x, as used in kdegraphics KPDF, might
allow remote attackers to execute arbitrary code via a crafted PDF
document that triggers a heap-based buffer overflow (CVE-2009-3606).
Integer overflow in the ObjectStream::ObjectStream function in XRef.cc
in Xpdf 3.x before 3.02pl4 and Poppler before 0.12.1, as used in
GPdf, kdegraphics KPDF, CUPS pdftops, and teTeX, might allow remote
attackers to execute arbitrary code via a crafted PDF document that
triggers a heap-based buffer overflow (CVE-2009-3608).
Integer overflow in the ImageStream::ImageStream function in Stream.cc
in Xpdf before 3.02pl4 and Poppler before 0.12.1, as used in GPdf,
kdegraphics KPDF, and CUPS pdftops, allows remote attackers to
cause a denial of service (application crash) via a crafted PDF
document that triggers a NULL pointer dereference or buffer over-read
(CVE-2009-3609).
This update fixes these vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:287");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1188", "CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609");
script_summary(english: "Check for the version of the xpdf package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xpdf-3.02-12.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpdf-common-3.02-12.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xpdf-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-1188", value:TRUE);
 set_kb_item(name:"CVE-2009-3603", value:TRUE);
 set_kb_item(name:"CVE-2009-3604", value:TRUE);
 set_kb_item(name:"CVE-2009-3606", value:TRUE);
 set_kb_item(name:"CVE-2009-3608", value:TRUE);
 set_kb_item(name:"CVE-2009-3609", value:TRUE);
}
exit(0, "Host is not affected");
