
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19985);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:177: hylafax");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:177 (hylafax).");
 script_set_attribute(attribute: "description", value: "faxcron, recvstats, and xferfaxstats in HylaFax 4.2.1 and earlier
allows local users to overwrite arbitrary files via a symlink attack
on temporary files. (CVE-2005-3069)
In addition, HylaFax has some provisional support for Unix domain
sockets, which is disabled in the default compile configuration. It is
suspected that a local user could create a fake /tmp/hyla.unix socket
and intercept fax traffic via this socket. In testing for this
vulnerability, with CONFIG_UNIXTRANSPORT disabled, it has been found
that client programs correctly exit before sending any data.
(CVE-2005-3070)
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:177");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-3069", "CVE-2005-3070");
script_summary(english: "Check for the version of the hylafax package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"hylafax-4.2.0-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.2.0-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.2.0-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-4.2.0-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-devel-4.2.0-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.2.0-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.2.0-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.2.0-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-4.2.0-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-devel-4.2.0-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.2.1-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.2.1-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.2.1-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-4.2.1-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-devel-4.2.1-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"hylafax-", release:"MDK10.1")
 || rpm_exists(rpm:"hylafax-", release:"MDK10.2")
 || rpm_exists(rpm:"hylafax-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3069", value:TRUE);
 set_kb_item(name:"CVE-2005-3070", value:TRUE);
}
exit(0, "Host is not affected");
