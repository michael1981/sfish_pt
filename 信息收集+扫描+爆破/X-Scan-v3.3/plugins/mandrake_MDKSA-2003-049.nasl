
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14033);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2003:049-1: kde3");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:049-1 (kde3).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered by the KDE team in the way that KDE
uses Ghostscript for processing PostScript and PDF files. A malicious
attacker could provide a carefully constructed PDF or PostScript file
to an end user (via web or mail) that could lead to the execution of
arbitrary commands as the user viewing the file. The vulnerability
can be triggered even by the browser generating a directory listing
with thumbnails.
All users are encouraged to upgrade to these new kdegraphics, kdebase,
and kdelibs packages that contain patches to correct the problem.
This issue is corrected upstream in KDE 3.0.5b and KDE 3.1.1a.
Update:
The previous update was missing a fix in kdebase specific to HP
machines. This has been corrected.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:049-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0204");
script_summary(english: "Check for the version of the kde3 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdebase-3.1-83.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.1-83.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-kdm-3.1-83.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-nsplugins-3.1-83.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kde3-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0204", value:TRUE);
}
exit(0, "Host is not affected");
