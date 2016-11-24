
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13972);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2002:072: mod_ssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:072 (mod_ssl).");
 script_set_attribute(attribute: "description", value: "A cross-site scripting vulnerability was discovered in mod_ssl by Joe
Orton. This only affects servers using a combination of wildcard DNS
and 'UseCanonicalName off' (which is not the default in Mandrake
Linux). With this setting turned off, Apache will attempt to use the
hostname:port that the client supplies, which is where the problem
comes into play. With this setting turned on (the default), Apache
constructs a self-referencing URL and will use ServerName and Port to
form the canonical name.
It is recommended that all users upgrade, regardless of the setting of
the 'UseCanonicalName' configuration option.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:072");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-1157");
script_summary(english: "Check for the version of the mod_ssl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mod_ssl-2.8.5-3.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.5-3.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.5-3.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.7-3.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.10-5.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mod_ssl-", release:"MDK7.2")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK8.0")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK8.1")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK8.2")
 || rpm_exists(rpm:"mod_ssl-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1157", value:TRUE);
}
exit(0, "Host is not affected");
