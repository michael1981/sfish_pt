
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36632);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:158: silc-toolkit");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:158 (silc-toolkit).");
 script_set_attribute(attribute: "description", value: "A vulnerability was found in the SILC toolkit before version 1.1.5
that allowed a remote attacker to cause a denial of service (crash),
or possibly execute arbitrary code via long input data (CVE-2008-1227).
A vulnerability was found in the SILC toolkit before version 1.1.7
that allowed a remote attacker to execute arbitrary code via a crafted
PKCS#2 message (CVE-2008-1552).
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:158");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-1227", "CVE-2008-1552");
script_summary(english: "Check for the version of the silc-toolkit package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libsilc-1.1_2-1.1.2-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsilcclient-1.1_2-1.1.2-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"silc-toolkit-1.1.2-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"silc-toolkit-devel-1.1.2-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"silc-toolkit-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2008-1227", value:TRUE);
 set_kb_item(name:"CVE-2008-1552", value:TRUE);
}
exit(0, "Host is not affected");
