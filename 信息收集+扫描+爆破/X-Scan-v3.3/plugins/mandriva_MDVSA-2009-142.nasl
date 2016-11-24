
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39552);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:142: jasper");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:142 (jasper).");
 script_set_attribute(attribute: "description", value: "Multiple security vulnerabilities has been identified and fixed
in jasper:
The jpc_qcx_getcompparms function in jpc/jpc_cs.c for the JasPer
JPEG-2000 library (libjasper) before 1.900 allows remote user-assisted
attackers to cause a denial of service (crash) and possibly corrupt
the heap via malformed image files, as originally demonstrated using
imagemagick convert (CVE-2007-2721).
Multiple integer overflows in JasPer 1.900.1 might allow
context-dependent attackers to have an unknown impact via a crafted
image file, related to integer multiplication for memory allocation
(CVE-2008-3520).
The jas_stream_tmpfile function in libjasper/base/jas_stream.c in
JasPer 1.900.1 allows local users to overwrite arbitrary files via
a symlink attack on a tmp.XXXXXXXXXX temporary file (CVE-2008-3521).
Buffer overflow in the jas_stream_printf function in
libjasper/base/jas_stream.c in JasPer 1.900.1 might allow
context-dependent attackers to have an unknown impact via
vectors related to the mif_hdr_put function and use of vsprintf
(CVE-2008-3522).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:142");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-2721", "CVE-2008-3520", "CVE-2008-3521", "CVE-2008-3522");
script_summary(english: "Check for the version of the jasper package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"jasper-1.900.1-3.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libjasper1-1.900.1-3.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libjasper1-devel-1.900.1-3.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libjasper1-static-devel-1.900.1-3.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"jasper-1.900.1-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libjasper1-1.900.1-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libjasper1-devel-1.900.1-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libjasper1-static-devel-1.900.1-4.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"jasper-1.900.1-5.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libjasper1-1.900.1-5.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libjasper-devel-1.900.1-5.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libjasper-static-devel-1.900.1-5.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"jasper-", release:"MDK2008.1")
 || rpm_exists(rpm:"jasper-", release:"MDK2009.0")
 || rpm_exists(rpm:"jasper-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2007-2721", value:TRUE);
 set_kb_item(name:"CVE-2008-3520", value:TRUE);
 set_kb_item(name:"CVE-2008-3521", value:TRUE);
 set_kb_item(name:"CVE-2008-3522", value:TRUE);
}
exit(0, "Host is not affected");
