
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37782);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVA-2008:159: curl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVA-2008:159 (curl).");
 script_set_attribute(attribute: "description", value: "An idiosyncratic feature of the Turkish language is that the letter 'i'
in Turkish is not the lower-case version of the letter 'I'. This issue
breaks standard POSIX string case comparison on strings containing
the character 'i'. This issue affected the curl package shipped with
Mandriva Linux 2009, which ultimately caused it to be incapable of
handling URIs of the form file:///somefile in Turkish locales. In turn,
curl is used by webkit, which is used by the Mandriva Linux Control
Center, ultimately resulting in the Control Center not rendering icons
in its user interface when run in Turkish locales. The bug likely also
has other implications for curl-based applications in Turkish locales.
The fixed package includes a fix for this issue, so that curl will
correctly handle file:///somefile URIs in Turkish locales. As a
consequence, the Mandriva Linux Control Center now properly renders
icons in Turkish locales.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVA-2008:159");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the curl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"curl-7.19.0-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"curl-examples-7.19.0-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcurl4-7.19.0-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcurl-devel-7.19.0-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
