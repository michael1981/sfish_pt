
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13956);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2002:054-1: gaim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:054-1 (gaim).");
 script_set_attribute(attribute: "description", value: "Versions of Gaim (an AOL instant message client) prior to 0.58 contain a
buffer overflow in the Jabber plug-in module. As well, a vulnerability
was discovered in the URL-handling code, where the 'manual' browser
command passes an untrusted string to the shell without reliable
quoting or escaping. This allows an attacker to execute arbitrary
commands on the user's machine with the user's permissions. Those
using the built-in browser commands are not vulnerable.
Update:
The 8.1 package had an incorrect dependency on perl. This package
has been replaced with a proper package. Please note the differing
md5 sums.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:054-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-0384", "CVE-2002-0989");
script_summary(english: "Check for the version of the gaim package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gaim-0.59.1-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"MDK8.1") )
{
 set_kb_item(name:"CVE-2002-0384", value:TRUE);
 set_kb_item(name:"CVE-2002-0989", value:TRUE);
}
exit(0, "Host is not affected");
