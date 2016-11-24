
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14139);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2004:040: libpng");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:040 (libpng).");
 script_set_attribute(attribute: "description", value: "Steve Grubb discovered that libpng would access memory that is out of
bounds when creating an error message. The impact of this bug is not
clear, but it could lead to a core dump in a program using libpng, or
could result in a DoS (Denial of Service) condition in a daemon that
uses libpng to process PNG imagaes.
The updated packages are patched to correct the vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:040");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0421");
script_summary(english: "Check for the version of the libpng package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libpng3-1.2.5-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.5-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.5-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-1.2.5-2.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.5-2.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.5-2.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-1.2.5-7.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.5-7.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.5-7.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libpng-", release:"MDK10.0")
 || rpm_exists(rpm:"libpng-", release:"MDK9.1")
 || rpm_exists(rpm:"libpng-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0421", value:TRUE);
}
exit(0, "Host is not affected");
