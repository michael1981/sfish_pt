
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14003);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:018: apcupsd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:018 (apcupsd).");
 script_set_attribute(attribute: "description", value: "A remote root vulnerability in slave setups and some buffer overflows
in the network information server code were discovered by the apcupsd
developers. They have been fixed in the latest unstable version,
3.10.5 which contains additional enhancements like USB support, and
the latest stable version, 3.8.6.
There are a few changes that need to be noted, such as the port has
changed from port 7000 to post 3551 for NIS, and the new config only
allows access from the localhost. Users may need to modify their
configuration files appropriately, depending upon their configuration.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:018");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0098", "CVE-2003-0099");
script_summary(english: "Check for the version of the apcupsd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apcupsd-3.10.5-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apcupsd-3.10.5-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apcupsd-3.10.5-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"apcupsd-", release:"MDK8.1")
 || rpm_exists(rpm:"apcupsd-", release:"MDK8.2")
 || rpm_exists(rpm:"apcupsd-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0098", value:TRUE);
 set_kb_item(name:"CVE-2003-0099", value:TRUE);
}
exit(0, "Host is not affected");
