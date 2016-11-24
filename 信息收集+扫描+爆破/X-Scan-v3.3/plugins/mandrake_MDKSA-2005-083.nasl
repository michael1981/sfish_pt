
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18237);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:083: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:083 (ethereal).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered in previous version of
Ethereal that have been fixed in the 0.10.11 release, including:
- The ANSI A and DHCP dissectors are vulnerable to format string
vulnerabilities.
- The DISTCC, FCELS, SIP, ISIS, CMIP, CMP, CMS, CRMF, ESS, OCSP,
PKIX1Explitit, PKIX Qualified, X.509, Q.931, MEGACO, NCP, ISUP, TCAP
and Presentation dissectors are vulnerable to buffer overflows.
- The KINK, WSP, SMB Mailslot, H.245, MGCP, Q.931, RPC, GSM and SMB
NETLOGON dissectors are vulnerable to pointer handling errors.
- The LMP, KINK, MGCP, RSVP, SRVLOC, EIGRP, MEGACO, DLSw, NCP and
L2TP dissectors are vulnerable to looping problems.
- The Telnet and DHCP dissectors could abort.
- The TZSP, Bittorrent, SMB, MGCP and ISUP dissectors could cause a
segmentation fault.
- The WSP, 802.3 Slow protocols, BER, SMB Mailslot, SMB, NDPS, IAX2,
RADIUS, SMB PIPE, MRDISC and TCAP dissectors could throw assertions.
- The DICOM, NDPS and ICEP dissectors are vulnerable to memory
handling errors.
- The GSM MAP, AIM, Fibre Channel,SRVLOC, NDPS, LDAP and NTLMSSP
dissectors could terminate abnormallly.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:083");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-1456", "CVE-2005-1457", "CVE-2005-1458", "CVE-2005-1459", "CVE-2005-1460", "CVE-2005-1461", "CVE-2005-1462", "CVE-2005-1463", "CVE-2005-1464", "CVE-2005-1465", "CVE-2005-1466", "CVE-2005-1467", "CVE-2005-1468", "CVE-2005-1469", "CVE-2005-1470");
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

if ( rpm_check( reference:"ethereal-0.10.11-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.11-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.11-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.11-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.11-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.11-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.11-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.11-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK10.1")
 || rpm_exists(rpm:"ethereal-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1456", value:TRUE);
 set_kb_item(name:"CVE-2005-1457", value:TRUE);
 set_kb_item(name:"CVE-2005-1458", value:TRUE);
 set_kb_item(name:"CVE-2005-1459", value:TRUE);
 set_kb_item(name:"CVE-2005-1460", value:TRUE);
 set_kb_item(name:"CVE-2005-1461", value:TRUE);
 set_kb_item(name:"CVE-2005-1462", value:TRUE);
 set_kb_item(name:"CVE-2005-1463", value:TRUE);
 set_kb_item(name:"CVE-2005-1464", value:TRUE);
 set_kb_item(name:"CVE-2005-1465", value:TRUE);
 set_kb_item(name:"CVE-2005-1466", value:TRUE);
 set_kb_item(name:"CVE-2005-1467", value:TRUE);
 set_kb_item(name:"CVE-2005-1468", value:TRUE);
 set_kb_item(name:"CVE-2005-1469", value:TRUE);
 set_kb_item(name:"CVE-2005-1470", value:TRUE);
}
exit(0, "Host is not affected");
