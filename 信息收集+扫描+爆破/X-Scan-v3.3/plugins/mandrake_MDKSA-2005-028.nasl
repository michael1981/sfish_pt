
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16294);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:028: ncpfs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:028 (ncpfs).");
 script_set_attribute(attribute: "description", value: "Erik Sjolund discovered two vulnerabilities in programs bundled with
ncpfs. Due to a flaw in nwclient.c, utilities that use the NetWare
client functions insecurely access files with elevated privileges
(CVE-2005-0013), and there is a potentially exploitable buffer overflow
in the ncplogin program (CVE-2005-0014).
As well, an older vulnerability found by Karol Wiesek is corrected with
these new versions of ncpfs. Karol found a buffer overflow in the
handling of the '-T' option in the ncplogin and ncpmap utilities
(CVE-2004-1079).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:028");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-1079", "CVE-2005-0013", "CVE-2005-0014");
script_summary(english: "Check for the version of the ncpfs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ipxutils-2.2.6-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libncpfs2.3-2.2.6-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libncpfs2.3-devel-2.2.6-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ncpfs-2.2.6-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ipxutils-2.2.6-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libncpfs2.3-2.2.6-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libncpfs2.3-devel-2.2.6-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ncpfs-2.2.6-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ncpfs-", release:"MDK10.0")
 || rpm_exists(rpm:"ncpfs-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-1079", value:TRUE);
 set_kb_item(name:"CVE-2005-0013", value:TRUE);
 set_kb_item(name:"CVE-2005-0014", value:TRUE);
}
exit(0, "Host is not affected");
