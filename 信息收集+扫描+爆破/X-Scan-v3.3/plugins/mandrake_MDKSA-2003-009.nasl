
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13994);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:009: cvs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:009 (cvs).");
 script_set_attribute(attribute: "description", value: "Two vulnerabilities were discoverd by Stefen Esser in the cvs program.
The first is an exploitable double free() bug within the server, which
can be used to execute arbitray code on the CVS server. To accomplish
this, the attacker must have an anonymous read-only login to the CVS
server. The second vulnerability is with the Checkin-prog and
Update-prog commands. If a client has write permission, he can use
these commands to execute programs outside of the scope of CVS, the
output of which will be sent as output to the client.
This update fixes the double free() vulnerability and removes the
Checkin-prog and Update-prog commands from CVS.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:009");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0015");
script_summary(english: "Check for the version of the cvs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cvs-1.11.4-2.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.4-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.4-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.4-2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.4-2.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"MDK7.2")
 || rpm_exists(rpm:"cvs-", release:"MDK8.0")
 || rpm_exists(rpm:"cvs-", release:"MDK8.1")
 || rpm_exists(rpm:"cvs-", release:"MDK8.2")
 || rpm_exists(rpm:"cvs-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0015", value:TRUE);
}
exit(0, "Host is not affected");
