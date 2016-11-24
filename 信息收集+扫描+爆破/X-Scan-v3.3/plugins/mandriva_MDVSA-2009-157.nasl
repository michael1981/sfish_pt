
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39874);
 script_version("$Revision: 1.2 $");
 script_name(english: "MDVSA-2009:157: perl-Compress-Raw-Zlib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:157 (perl-Compress-Raw-Zlib).");
 script_set_attribute(attribute: "description", value: "A vulnerability has been found and corrected in perl-Compress-Raw-Zlib:
Off-by-one error in the inflate function in Zlib.xs in
Compress::Raw::Zlib Perl module before 2.017, as used in AMaViS,
SpamAssassin, and possibly other products, allows context-dependent
attackers to cause a denial of service (hang or crash) via a crafted
zlib compressed stream that triggers a heap-based buffer overflow,
as exploited in the wild by Trojan.Downloader-71014 in June 2009
(CVE-2009-1391).
This update provides fixes for this vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:157");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1391");
script_summary(english: "Check for the version of the perl-Compress-Raw-Zlib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"perl-Compress-Raw-Zlib-2.008-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Compress-Raw-Zlib-2.015-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Compress-Raw-Zlib-2.015-2.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"perl-Compress-Raw-Zlib-", release:"MDK2008.1")
 || rpm_exists(rpm:"perl-Compress-Raw-Zlib-", release:"MDK2009.0")
 || rpm_exists(rpm:"perl-Compress-Raw-Zlib-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-1391", value:TRUE);
}
exit(0, "Host is not affected");
