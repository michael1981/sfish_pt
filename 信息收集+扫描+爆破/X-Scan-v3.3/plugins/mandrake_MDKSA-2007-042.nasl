
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24655);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:042: smb4k");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:042 (smb4k).");
 script_set_attribute(attribute: "description", value: "Kees Cook performed an audit on the Smb4K program and discovered a
number of vulnerabilities and security weaknesses that have been
addressed and corrected in Smb4K 0.8.0 which is being provided with
this update.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:042");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-0472", "CVE-2007-0473", "CVE-2007-0474", "CVE-2007-0475");
script_summary(english: "Check for the version of the smb4k package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libsmb4k0-0.8.0-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libsmb4k0-devel-0.8.0-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"smb4k-0.8.0-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"smb4k-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2007-0472", value:TRUE);
 set_kb_item(name:"CVE-2007-0473", value:TRUE);
 set_kb_item(name:"CVE-2007-0474", value:TRUE);
 set_kb_item(name:"CVE-2007-0475", value:TRUE);
}
exit(0, "Host is not affected");
