
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14039);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:055: kopete");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:055 (kopete).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered in versions of kopete, a KDE instant
messenger client, prior to 0.6.2. This vulnerabiliy is in the GnuPG
plugin that allows for users to send each other GPG-encrypted instant
messages. The plugin passes encrypted messages to gpg, but does no
checking to sanitize the commandline passed to gpg. This can allow
remote users to execute arbitrary code, with the permissions of the
user running kopete, on the local system.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:055");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0256");
script_summary(english: "Check for the version of the kopete package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kopete-0.6.2-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libkopete1-0.6.2-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kopete-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0256", value:TRUE);
}
exit(0, "Host is not affected");
