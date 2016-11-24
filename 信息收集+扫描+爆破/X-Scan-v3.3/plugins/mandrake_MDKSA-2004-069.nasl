
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14168);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2004:069: ipsec-tools");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:069 (ipsec-tools).");
 script_set_attribute(attribute: "description", value: "A vulnerability in racoon prior to version 20040408a would allow a
remote attacker to cause a DoS (memory consumption) via an ISAKMP
packet with a large length field.
Another vulnerability in racoon was discovered where, when using RSA
signatures, racoon would validate the X.509 certificate but would not
validate the signature. This can be exploited by an attacker sending
a valid and trusted X.509 certificate and any private key. Using this,
they could perform a man-in-the-middle attack and initiate an
unauthorized connection. This has been fixed in ipsec-tools 0.3.3.
The updated packages contain patches backported from 0.3.3 to correct
the problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:069");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0403");
script_summary(english: "Check for the version of the ipsec-tools package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ipsec-tools-0.2.5-0.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libipsec-tools0-0.2.5-0.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ipsec-tools-", release:"MDK10.0") )
{
 set_kb_item(name:"CVE-2004-0403", value:TRUE);
}
exit(0, "Host is not affected");
