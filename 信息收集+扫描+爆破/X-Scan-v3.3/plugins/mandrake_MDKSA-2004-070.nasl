
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14820);
 script_version ("$Revision: 1.10 $");
 script_name(english: "MDKSA-2004:070-1: super-freeswan");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:070-1 (super-freeswan).");
 script_set_attribute(attribute: "description", value: "Thomas Walpuski discovered a vulnerability in the X.509 handling of
super-freeswan, openswan, strongSwan, and FreeS/WAN with the X.509
patch applied. This vulnerability allows an attacker to make up their
own Certificate Authority that can allow them to impersonate the
identity of a valid DN. As well, another hole exists in the CA
checking code that could create an endless loop in certain instances.
Mandrakesoft encourages all users who use FreeS/WAN or super-freeswan
to upgrade to the updated packages which are patched to correct these
flaws.
Update:
Due to a build error, the super-freeswan packages did not include the
pluto program. The updated packages fix this error.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:070-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0590");
script_summary(english: "Check for the version of the super-freeswan package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"super-freeswan-1.99.8-8.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"super-freeswan-doc-1.99.8-8.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"super-freeswan-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0590", value:TRUE);
}
exit(0, "Host is not affected");
