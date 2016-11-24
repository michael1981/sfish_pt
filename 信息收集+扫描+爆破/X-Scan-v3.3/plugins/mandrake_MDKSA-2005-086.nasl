
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18275);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:086: gaim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:086 (gaim).");
 script_set_attribute(attribute: "description", value: "More vulnerabilities have been found in the gaim instant messaging
client. A stack-based buffer overflow bug was found in how gaim
processes a message containing a URL; a remote attacker could send a
carefully crafted message to cause the execution of arbitrary code on
the user's machine (CVE-2005-1261).
Another bug was found in how gaim handles malformed MSN messages; an
attacker could send a carefully crafted MSN message that would cause
gaim to crash (CVE-2005-1262).
Gaim version 1.3.0 fixes these issues and is provided with this
update.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:086");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-1261", "CVE-2005-1262");
script_summary(english: "Check for the version of the gaim package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gaim-1.3.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-devel-1.3.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-gevolution-1.3.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-1.3.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-tcl-1.3.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-1.3.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-1.3.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-1.3.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-devel-1.3.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-gevolution-1.3.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-1.3.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-silc-1.3.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-tcl-1.3.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-1.3.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-1.3.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"MDK10.1")
 || rpm_exists(rpm:"gaim-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1261", value:TRUE);
 set_kb_item(name:"CVE-2005-1262", value:TRUE);
}
exit(0, "Host is not affected");
