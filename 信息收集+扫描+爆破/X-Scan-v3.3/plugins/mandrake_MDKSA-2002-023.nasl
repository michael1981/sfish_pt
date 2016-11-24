
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13931);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2002:023-1: zlib-pkgs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:023-1 (zlib-pkgs).");
 script_set_attribute(attribute: "description", value: "Matthias Clasen found a security issue in zlib that, when provided with
certain input, causes zlib to free an area of memory twice. This
'double free' bug can be used to crash any programs that take untrusted
compressed input, such as web browsers, email clients, image viewing
software, etc. This vulnerability can be used to perform Denial of
Service attacks and, quite possibly, the execution of arbitrary code on
the affected system.
MandrakeSoft has published two advisories concerning this incident:
MDKSA-2002:022 - zlib
MDKSA-2002:023 - packages containing zlib
Update:
Additional package are now available. For a list of prior packages
released, please see MDKSA-2002:023. The noted packages below are in
addition to MDKSA-2002:023; no packages have been replaced.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:023-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-0059");
script_summary(english: "Check for the version of the zlib-pkgs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mirrordir-0.10.44-4.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mirrordir-0.10.44-4.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdiffie1-0.10.49-4.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdiffie1-devel-0.10.49-4.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgcj-2.96-2.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgcj-devel-2.96-2.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmirrordirz1-0.10.49-4.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmirrordirz1-devel-0.10.49-4.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mirrordir-0.10.49-4.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdiffie1-0.10.49-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libdiffie1-devel-0.10.49-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgcj-2.96-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgcj-devel-2.96-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmirrordirz1-0.10.49-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmirrordirz1-devel-0.10.49-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mirrordir-0.10.49-4.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"zlib-pkgs-", release:"MDK7.1")
 || rpm_exists(rpm:"zlib-pkgs-", release:"MDK7.2")
 || rpm_exists(rpm:"zlib-pkgs-", release:"MDK8.0")
 || rpm_exists(rpm:"zlib-pkgs-", release:"MDK8.1") )
{
 set_kb_item(name:"CVE-2002-0059", value:TRUE);
}
exit(0, "Host is not affected");
