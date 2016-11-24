
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14679);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2004:090: zlib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:090 (zlib).");
 script_set_attribute(attribute: "description", value: "Due to a Debian bug report, a Denial of Service vulnerability was
discovered in the zlib compression library versions 1.2.x, in the
inflate() and inflateBack() functions. Older versions of zlib are
not affected.
Once the updated packages have been installed, all programs linked
against zlib must be restarted for the new packages to take effect.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:090");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0797");
script_summary(english: "Check for the version of the zlib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"zlib1-1.2.1-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.2.1-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"zlib-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0797", value:TRUE);
}
exit(0, "Host is not affected");
