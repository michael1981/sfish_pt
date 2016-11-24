
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36369);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:005: libexif");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:005 (libexif).");
 script_set_attribute(attribute: "description", value: "An infinite recursion flaw was found in the way that libexif parses
Exif image tags. A carefully crafted Exif image file opened by an
application linked against libexif could cause the application to crash
(CVE-2007-6351).
An integer overflow flaw was also found in how libexif parses
Exif image tags. A carefully crafted Exif image file opened by
an application linked against libexif could cause the application
to crash or execute arbitrary code with the privileges of the user
executing the application (CVE-2007-6352).
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:005");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-6351", "CVE-2007-6352");
script_summary(english: "Check for the version of the libexif package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libexif12-0.6.13-2.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif12-devel-0.6.13-2.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif12-0.6.13-4.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif12-devel-0.6.13-4.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif-devel-0.6.16-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libexif12-0.6.16-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libexif-", release:"MDK2007.0")
 || rpm_exists(rpm:"libexif-", release:"MDK2007.1")
 || rpm_exists(rpm:"libexif-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2007-6351", value:TRUE);
 set_kb_item(name:"CVE-2007-6352", value:TRUE);
}
exit(0, "Host is not affected");
