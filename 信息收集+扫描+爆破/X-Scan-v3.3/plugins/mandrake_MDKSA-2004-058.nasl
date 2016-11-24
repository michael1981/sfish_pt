
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14157);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2004:058: cvs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:058 (cvs).");
 script_set_attribute(attribute: "description", value: "Another vulnerability was discovered related to 'Entry' lines in
cvs, by the development team (CVE-2004-0414).
As well, Stefan Esser and Sebastian Krahmer performed an audit on the
cvs source code and discovered a number of other problems, including:
A double-free condition in the server code is exploitable
(CVE-2004-0416).
By sending a large number of arguments to the CVS server, it is
possible to cause it to allocate a huge amount of memory which does
not fit into the address space, causing an error (CVE-2004-0417).
It was found that the serve_notify() function would write data out
of bounds (CVE-2004-0418).
The provided packages update cvs to 1.11.16 and include patches to
correct all of these problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:058");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418");
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

if ( rpm_check( reference:"cvs-1.11.16-1.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.16-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.16-1.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"MDK10.0")
 || rpm_exists(rpm:"cvs-", release:"MDK9.1")
 || rpm_exists(rpm:"cvs-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0414", value:TRUE);
 set_kb_item(name:"CVE-2004-0416", value:TRUE);
 set_kb_item(name:"CVE-2004-0417", value:TRUE);
 set_kb_item(name:"CVE-2004-0418", value:TRUE);
}
exit(0, "Host is not affected");
