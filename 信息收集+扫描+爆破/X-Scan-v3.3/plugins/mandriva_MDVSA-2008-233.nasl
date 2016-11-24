
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36292);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:233: libcdaudio");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:233 (libcdaudio).");
 script_set_attribute(attribute: "description", value: "A heap overflow was found in the CDDB retrieval code of libcdaudio,
which could result in the execution of arbitrary code (CVE-2008-5030).
In addition, the fixes for CVE-2005-0706 were not applied to newer
libcdaudio packages as shipped with Mandriva Linux, so the patch to fix
that issue has been applied to 2008.1 and 2009.0 (this was originally
fixed in MDKSA-2005:075). This issue is a buffer overflow flaw found
by Joseph VanAndel. Corporate 3.0 has this fix already applied.
The updated packages have been patched to prevent these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:233");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0706", "CVE-2008-5030");
script_summary(english: "Check for the version of the libcdaudio package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libcdaudio1-0.99.12-5.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcdaudio1-devel-0.99.12-5.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcdaudio1-0.99.12-6.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcdaudio1-devel-0.99.12-6.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libcdaudio-", release:"MDK2008.1")
 || rpm_exists(rpm:"libcdaudio-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2005-0706", value:TRUE);
 set_kb_item(name:"CVE-2008-5030", value:TRUE);
}
exit(0, "Host is not affected");
