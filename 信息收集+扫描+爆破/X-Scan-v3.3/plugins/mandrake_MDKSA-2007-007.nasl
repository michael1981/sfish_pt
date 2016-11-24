
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24623);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:007: nvidia");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:007 (nvidia).");
 script_set_attribute(attribute: "description", value: "A vulnerability in the NVIDIA Xorg driver was discovered by Derek
Abdine who found that it did not correctly verify the size of buffers
used to render text glyphs, resulting in a crash of the server when
displaying very long strings of text. If a user was tricked into
viewing a specially crafted series of glyphs, this flaw could be
exploited to run arbitrary code with root privileges.
This vulnerability exists in driver versions 1.0-8762 and 1.0-8774 and
is corrected in 1.0-8776 which is being provided with this update.
The packages can be found in the non-free/updates media.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:007");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-5379");
script_summary(english: "Check for the version of the nvidia package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dkms-nvidia-8776-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-8776-1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-kernel-2.6.17-5mdv-8776-1mdk", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-kernel-2.6.17-5mdventerprise-8776-1mdk", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nvidia-kernel-2.6.17-5mdvlegacy-8776-1mdk", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"nvidia-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-5379", value:TRUE);
}
exit(0, "Host is not affected");
