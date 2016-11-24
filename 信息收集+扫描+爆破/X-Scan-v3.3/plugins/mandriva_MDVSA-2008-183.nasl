
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37949);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:183: opensc");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:183 (opensc).");
 script_set_attribute(attribute: "description", value: "Chaskiel M Grundman found that OpenSC would initialize smart cards
with the Siemens CardOS M4 card operating system without proper access
rights. This allowed everyone to change the card's PIN without first
having the PIN or PUK, or the superuser's PIN or PUK (CVE-2008-2235).
Please note that this issue can not be used to discover the PIN on
a card. If the PIN on a card is the same that was always there,
it is unlikely that this vulnerability has been exploited. As well,
this issue only affects smart cards and USB crypto tokens based on
Siemens CardOS M4, and then only those devices that were initialized
by OpenSC. Users of other smart cards or USB crypto tokens, or cards
that were not initialized by OpenSC, are not affected.
After applying the update, executing 'pkcs15-tool -T' will indicate
whether the card is fine or vulnerable. If the card is vulnerable, the
security settings need to be updated by executing 'pkcs15-tool -T -U'.
The updated packages have been patched to prevent this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:183");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-2235");
script_summary(english: "Check for the version of the opensc package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libopensc2-0.11.1-3.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopensc2-devel-0.11.1-3.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-plugin-opensc-0.11.1-3.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opensc-0.11.1-3.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopensc2-0.11.3-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopensc-devel-0.11.3-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-plugin-opensc-0.11.3-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opensc-0.11.3-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopensc2-0.11.3-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopensc-devel-0.11.3-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-plugin-opensc-0.11.3-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"opensc-0.11.3-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"opensc-", release:"MDK2007.1")
 || rpm_exists(rpm:"opensc-", release:"MDK2008.0")
 || rpm_exists(rpm:"opensc-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-2235", value:TRUE);
}
exit(0, "Host is not affected");
