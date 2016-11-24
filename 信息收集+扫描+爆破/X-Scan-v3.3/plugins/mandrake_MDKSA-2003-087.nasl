
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14069);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:087: gkrellm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:087 (gkrellm).");
 script_set_attribute(attribute: "description", value: "A buffer overflow was discovered in gkrellmd, the server component of
the gkrellm monitor package, in versions of gkrellm 2.1.x prior to
2.1.14. This buffer overflow occurs while reading data from connected
gkrellm clients and can lead to possible arbitrary code execution as
the user running the gkrellmd server.
Updated packages are available for Mandrake Linux 9.1 which correct the
problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:087");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0723");
script_summary(english: "Check for the version of the gkrellm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gkrellm-2.1.7a-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gkrellm-devel-2.1.7a-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gkrellm-server-2.1.7a-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gkrellm-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0723", value:TRUE);
}
exit(0, "Host is not affected");
