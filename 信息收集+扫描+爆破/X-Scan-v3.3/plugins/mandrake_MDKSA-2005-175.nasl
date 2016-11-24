
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19984);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:175: texinfo");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:175 (texinfo).");
 script_set_attribute(attribute: "description", value: "Frank Lichtenheld has discovered that texindex insecurely creates
temporary files with predictable filenames. This is exploitable if
a local attacker were to create symbolic links in the temporary files
directory, pointing to a valid file on the filesystem. When texindex
is executed, the file would be overwitten with the rights of the user
running texindex.
The updated packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:175");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-3011");
script_summary(english: "Check for the version of the texinfo package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"info-4.7-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"info-install-4.7-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"texinfo-4.7-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"info-4.8-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"info-install-4.8-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"texinfo-4.8-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"info-4.8-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"info-install-4.8-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"texinfo-4.8-1.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"texinfo-", release:"MDK10.1")
 || rpm_exists(rpm:"texinfo-", release:"MDK10.2")
 || rpm_exists(rpm:"texinfo-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3011", value:TRUE);
}
exit(0, "Host is not affected");
