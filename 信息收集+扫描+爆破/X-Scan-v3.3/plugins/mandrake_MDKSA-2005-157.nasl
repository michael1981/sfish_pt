
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19912);
 script_version ("$Revision: 1.4 $");
 script_name(english: "MDKSA-2005:157: smb4k");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:157 (smb4k).");
 script_set_attribute(attribute: "description", value: "A severe security issue has been discovered in Smb4K. By linking a
simple text file FILE to /tmp/smb4k.tmp or /tmp/sudoers, an attacker
could get access to the full contents of the /etc/super.tab or
/etc/sudoers file, respectively, because Smb4K didn't check for the
existance of these files before writing any contents. When using super,
the attack also resulted in /etc/super.tab being a symlink to FILE.
Affected are all versions of the 0.4, 0.5, and 0.6 series of Smb4K.
The updated packages have been patched to correct this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:157");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-2851");
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

if ( rpm_check( reference:"smb4k-0.4.0-3.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"smb4k-0.5.1-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"smb4k-", release:"MDK10.1")
 || rpm_exists(rpm:"smb4k-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2851", value:TRUE);
}
exit(0, "Host is not affected");
