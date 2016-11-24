
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15546);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2004:110: gaim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:110 (gaim).");
 script_set_attribute(attribute: "description", value: "More vulnerabilities have been discovered in the gaim instant
messenger client. The vulnerabilities pertinent to version 0.75,
which is the version shipped with Mandrakelinux 10.0, are: installing
smiley themes could allow remote attackers to execute arbitrary
commands via shell metacharacters in the filename of the tar file that
is dragged to the smiley selector. There is also a buffer overflow in
the way gaim handles receiving very long URLs.
The provided packages have been patched to fix these problems. These
issues, amongst others, have been fixed upstream in version 0.82.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:110");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0784", "CVE-2004-0785");
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

if ( rpm_check( reference:"gaim-0.75-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-encrypt-0.75-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-festival-0.75-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-0.75-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-0.75-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-0.75-5.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0784", value:TRUE);
 set_kb_item(name:"CVE-2004-0785", value:TRUE);
}
exit(0, "Host is not affected");
