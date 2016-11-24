
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14162);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2004:063: libpng");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:063 (libpng).");
 script_set_attribute(attribute: "description", value: "A buffer overflow vulnerability was discovered in libpng due to a wrong
calculation of some loop offset values. This buffer overflow can lead
to Denial of Service or even remote compromise.
This vulnerability was initially patched in January of 2003, but it
has since been noted that fixes were required in two additional places
that had not been corrected with the earlier patch. This update uses
an updated patch to fix all known issues.
After the upgrade, all applications that use libpng should be
restarted. Many applications are linked to libpng, so if you are
unsure of what applications to restart, you may wish to reboot the
system. Mandrakesoft encourages all users to upgrade immediately.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:063");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-1363");
script_summary(english: "Check for the version of the libpng package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libpng3-1.2.5-10.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.5-10.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.5-10.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-1.2.5-2.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.5-2.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.5-2.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-1.2.5-7.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-devel-1.2.5-7.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpng3-static-devel-1.2.5-7.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libpng-", release:"MDK10.0")
 || rpm_exists(rpm:"libpng-", release:"MDK9.1")
 || rpm_exists(rpm:"libpng-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2002-1363", value:TRUE);
}
exit(0, "Host is not affected");
