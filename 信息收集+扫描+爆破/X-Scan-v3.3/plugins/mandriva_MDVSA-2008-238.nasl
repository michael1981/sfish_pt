
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36234);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDVSA-2008:238: libsamplerate");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:238 (libsamplerate).");
 script_set_attribute(attribute: "description", value: "A buffer overflow was found by Russell O'Conner in the libsamplerate
library versions prior to 0.1.4 that could possibly lead to the
execution of arbitrary code via a specially crafted audio file
(CVE-2008-5008).
The updated packages have been patched to prevent this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:238");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-5008");
script_summary(english: "Check for the version of the libsamplerate package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libsamplerate0-0.1.3-0.pre6.3.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsamplerate-devel-0.1.3-0.pre6.3.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsamplerate-progs-0.1.3-0.pre6.3.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsamplerate0-0.1.3-0.pre6.3.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsamplerate-devel-0.1.3-0.pre6.3.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsamplerate-progs-0.1.3-0.pre6.3.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libsamplerate-", release:"MDK2008.0")
 || rpm_exists(rpm:"libsamplerate-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-5008", value:TRUE);
}
exit(0, "Host is not affected");
