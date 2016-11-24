
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20433);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2005:188: graphviz");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:188 (graphviz).");
 script_set_attribute(attribute: "description", value: "Javier Fern ndez-Sanguino Pe a discovered insecure temporary file
creation in graphviz, a rich set of graph drawing tools, that can be
exploited to overwrite arbitrary files by a local attacker.
The updated packages have been patched to address this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:188");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

 script_cve_id("CVE-2005-4803");
script_summary(english: "Check for the version of the graphviz package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"graphviz-2.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgraphviz7-2.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgraphviz7-devel-2.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgraphviztcl7-2.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgraphviztcl7-devel-2.2-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"graphviz-2.2.1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgraphviz7-2.2.1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgraphviz7-devel-2.2.1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgraphviztcl7-2.2.1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgraphviztcl7-devel-2.2.1-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"graphviz-", release:"MDK10.2")
 || rpm_exists(rpm:"graphviz-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2965", value:TRUE);
}
exit(0, "Host is not affected");
