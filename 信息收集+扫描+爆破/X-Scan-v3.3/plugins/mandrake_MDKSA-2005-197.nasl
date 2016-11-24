
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20125);
 script_version ("$Revision: 1.4 $");
 script_name(english: "MDKSA-2005:197: unzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:197 (unzip).");
 script_set_attribute(attribute: "description", value: "Unzip 5.51 and earlier does not properly warn the user when
extracting setuid or setgid files, which may allow local users
to gain privileges. (CVE-2005-0602)
Imran Ghory found a race condition in the handling of output files.
While a file was unpacked by unzip, a local attacker with write
permissions to the target directory could exploit this to change the
permissions of arbitrary files of the unzip user. This affects
versions of unzip 5.52 and lower (CVE-2005-2475)
The updated packages have been patched to address these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:197");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0602", "CVE-2005-2475");
script_summary(english: "Check for the version of the unzip package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"unzip-5.51-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"unzip-5.51-1.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"unzip-5.52-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"unzip-", release:"MDK10.1")
 || rpm_exists(rpm:"unzip-", release:"MDK10.2")
 || rpm_exists(rpm:"unzip-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-0602", value:TRUE);
 set_kb_item(name:"CVE-2005-2475", value:TRUE);
}
exit(0, "Host is not affected");
