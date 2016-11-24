
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37016);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:038: gd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:038 (gd).");
 script_set_attribute(attribute: "description", value: "Buffer overflow in the LWZReadByte() function in gd_gif_in.c in GD
prior to 2.0.34 allows remote attackers to have an unknown impact
via a GIF file with input_code_size greater than MAX_LWZ_BITS, which
triggers an overflow when initializing the table array.
This was originally fixed in PHP's embedded GD with MDKSA-2006:162;
patches had not been applied to the system libgd at that time.
The updated packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:038");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4484");
script_summary(english: "Check for the version of the gd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gd-utils-2.0.33-5.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgd2-2.0.33-5.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgd2-devel-2.0.33-5.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgd2-static-devel-2.0.33-5.4mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gd-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-4484", value:TRUE);
}
exit(0, "Host is not affected");
