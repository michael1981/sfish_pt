
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38708);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:108: zsh");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:108 (zsh).");
 script_set_attribute(attribute: "description", value: "A stack-based buffer overflow was found in the zsh command
interpreter. An attacker could use this flaw to cause a denial of
service (zsh crash), when providing a specially-crafted string as
input to the zsh shell (CVE-2009-1214, CVE-2009-1215).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:108");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1214", "CVE-2009-1215");
script_summary(english: "Check for the version of the zsh package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"zsh-4.3.5-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zsh-doc-4.3.5-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zsh-4.3.6-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zsh-doc-4.3.6-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"zsh-", release:"MDK2008.1")
 || rpm_exists(rpm:"zsh-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-1214", value:TRUE);
 set_kb_item(name:"CVE-2009-1215", value:TRUE);
}
exit(0, "Host is not affected");
