
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13978);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2002:080: kdenetwork");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:080 (kdenetwork).");
 script_set_attribute(attribute: "description", value: "The SuSE security team discovered two vulnerabilities in the KDE
lanbrowsing service during an audit. The LISa network daemon and
'reslisa', a restricted version of LISa are used to identify servers
on the local network by using the URL type 'lan://' and 'rlan://'
respectively. A buffer overflow was discovered in the lisa daemon
that can be exploited by an attacker on the local network to obtain
root privilege on a machine running the lisa daemon. Another
buffer overflow was found in the lan:// URL handler, which can be
exploited by a remote attacker to gain access to the victim user's
account.
Only Mandrake Linux 9.0 comes with the LISa network daemon; all
previous versions do not contain the network daemon and are as such
not vulnerable.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:080");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the kdenetwork package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdenetwork-3.0.3-15.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdenetwork-devel-3.0.3-15.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lisa-3.0.3-15.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
