
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42097);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:272: libmikmod");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:272 (libmikmod).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in libmikmod:
libmikmod 3.1.9 through 3.2.0, as used by MikMod, SDL-mixer, and
possibly other products, relies on the channel count of the last
loaded song, rather than the currently playing song, for certain
playback calculations, which allows user-assisted attackers to cause
a denial of service (application crash) by loading multiple songs
(aka MOD files) with different numbers of channels (CVE-2007-6720).
libmikmod 3.1.11 through 3.2.0, as used by MikMod and possibly other
products, allows user-assisted attackers to cause a denial of service
(application crash) by loading an XM file (CVE-2009-0179).
This update fixes these vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:272");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-6720", "CVE-2009-0179");
script_summary(english: "Check for the version of the libmikmod package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libmikmod2-3.1.11a-10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmikmod-devel-3.1.11a-10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmikmod3-3.2.0-0.beta2.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmikmod-devel-3.2.0-0.beta2.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libmikmod-", release:"MDK2008.1")
 || rpm_exists(rpm:"libmikmod-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2007-6720", value:TRUE);
 set_kb_item(name:"CVE-2009-0179", value:TRUE);
}
exit(0, "Host is not affected");
