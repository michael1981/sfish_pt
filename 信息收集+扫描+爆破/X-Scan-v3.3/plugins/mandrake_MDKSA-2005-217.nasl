
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20449);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2005:217: netpbm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:217 (netpbm).");
 script_set_attribute(attribute: "description", value: "Greg Roelofs discovered and fixed several buffer overflows in
pnmtopng which is also included in netpbm, a collection of
graphic conversion utilities, that can lead to the execution of
arbitrary code via a specially crafted PNM file.
Multiple buffer overflows in pnmtopng in netpbm 10.0 and
earlier allow attackers to execute arbitrary code via a
crafted PNM file. (CVE-2005-3632)
An off-by-one buffer overflow in pnmtopng, when using the -alpha
command line option, allows attackers to cause a denial of
service (crash) and possibly execute arbitrary code via a
crafted PNM file with exactly 256 colors. (CVE-2005-3662)
The updated packages have been patched to correct this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:217");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-3632", "CVE-2005-3662");
script_summary(english: "Check for the version of the netpbm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libnetpbm9-9.24-8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-devel-9.24-8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnetpbm9-static-devel-9.24-8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"netpbm-9.24-8.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"netpbm-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-3632", value:TRUE);
 set_kb_item(name:"CVE-2005-3662", value:TRUE);
}
exit(0, "Host is not affected");
