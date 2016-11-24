
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22013);
 script_version ("$Revision: 1.4 $");
 script_name(english: "MDKSA-2006:117-1: libmms");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:117-1 (libmms).");
 script_set_attribute(attribute: "description", value: "Stack-based buffer overflow in MiMMS 0.0.9 allows remote attackers to cause
a denial of service (application crash) and possibly execute arbitrary code
via the (1) send_command, (2) string_utf16, (3) get_data, and (4)
get_media_packet functions, and possibly other functions. Libmms uses the
same vulnerable code.
Update:
The previous update for libmms had an incorrect/incomplete patch. This
update includes a more complete fix for the issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:117-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-2200");
script_summary(english: "Check for the version of the libmms package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libmms0-0.1-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmms0-devel-0.1-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libmms-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2200", value:TRUE);
}
exit(0, "Host is not affected");
