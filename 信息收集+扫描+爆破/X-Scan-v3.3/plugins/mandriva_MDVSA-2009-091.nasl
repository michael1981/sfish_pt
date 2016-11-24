
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37785);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:091: mod_perl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:091 (mod_perl).");
 script_set_attribute(attribute: "description", value: "A vulnerability has been found and corrected in mod_perl v1.x and v2.x:
Cross-site scripting (XSS) vulnerability in Status.pm in Apache::Status
and Apache2::Status in mod_perl1 and mod_perl2 for the Apache HTTP
Server, when /perl-status is accessible, allows remote attackers to
inject arbitrary web script or HTML via the URI (CVE-2009-0796).
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:091");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-0796");
script_summary(english: "Check for the version of the mod_perl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apache-mod_perl-2.0.4-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_perl-devel-2.0.4-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_perl-2.0.4-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-mod_perl-devel-2.0.4-2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mod_perl-", release:"MDK2008.1")
 || rpm_exists(rpm:"mod_perl-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-0796", value:TRUE);
}
exit(0, "Host is not affected");
