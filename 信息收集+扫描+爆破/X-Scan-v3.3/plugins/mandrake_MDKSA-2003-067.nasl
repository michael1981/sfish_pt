
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14050);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:067: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:067 (ethereal).");
 script_set_attribute(attribute: "description", value: "Several vulnerabilities in ethereal were discovered by Timo Sirainen.
Integer overflows were found in the Mount and PPP dissectors, as well
as one-byte buffer overflows in the AIM, GIOP Gryphon, OSPF, PPTP,
Quake, Quake2, Quake3, Rsync, SMB, SMPP, and TSP dissectors. These
vulnerabilties were corrected in ethereal 0.9.12.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:067");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0356", "CVE-2003-0357");
script_summary(english: "Check for the version of the ethereal package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ethereal-0.9.12-1.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0356", value:TRUE);
 set_kb_item(name:"CVE-2003-0357", value:TRUE);
}
exit(0, "Host is not affected");
