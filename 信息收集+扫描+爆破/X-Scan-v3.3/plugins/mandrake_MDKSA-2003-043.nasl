
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14027);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2003:043-1: krb5");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:043-1 (krb5).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilties have been found in the Kerberos network
authentication system. The MIT Kerberos team have released an
advisory detailing these vulnerabilties, a description of which
follows.
An integer signedness error in the ASN.1 decoder before version 1.2.5
allows remote attackers to cause a crash of the server via a large
unsigned data element length, which is later used as a negative
value (CVE-2002-0036). Mandrake Linux 9.0+ is not affected by
this problem.
Vulnerabilties have been found in the RPC library used by the kadmin
service. A faulty length check in the RPC library exposes kadmind to
an integer overflow which can be used to crash kadmind (CVE-2003-0028).
The KDC (Key Distribution Center) before version 1.2.5 allows remote,
authenticated attackers to cause a crash on KDCs within the same realm
using a certain protocol that causes a null dereference
(CVE-2003-0058). Mandrake Linux 9.0+ is not affected by this problem.
Users from one realm can impersonate users in other realms that have
the same inter-realm keys due to a vulnerability in Kerberos 1.2.3
and earlier (CVE-2003-0059). Mandrake Linux 9.0+ is not affected by
this problem.
The KDC allows remote, authenticated users to cause a crash on KDCs
within the same realm using a certain protocol request that causes an
out-of-bounds read of an array (CVE-2003-0072).
The KDC allows remote, authenticated users to cause a crash on KDCs
within the same realm using a certain protocol request that causes the
KDC to corrupt its heap (CVE-2003-0082).
Vulnerabilities have been discovered in the Kerberos IV authentication
protocol which allow an attacker with knowledge of a cross-realm key,
which is shared in another realm, to impersonate a principle in that
realm to any service in that realm. This vulnerability can only
be closed by disabling cross-realm authentication in Kerberos IV
(CVE-2003-0138).
Vulnerabilities have been discovered in the support for triple-DES
keys in the Kerberos IV authentication protocol which is included
in MIT Kerberos (CVE-2003-0139).
MandrakeSoft encourages all users to upgrade to these updated packages
immediately which contain patches to correct all of the previously
noted vulnerabilities. These packages also disable Kerberos IV
cross-realm authentication by default.
Update:
The packages for Mandrake Linux 9.1 and 9.1/PPC were not GPG-signed.
This has been fixed and as a result the md5sums have changed. Thanks
to Mark Lyda for pointing this out.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:043-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-0036", "CVE-2003-0028", "CVE-2003-0058", "CVE-2003-0059", "CVE-2003-0072", "CVE-2003-0082", "CVE-2003-0138", "CVE-2003-0139");
script_summary(english: "Check for the version of the krb5 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ftp-client-krb5-1.2.7-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ftp-server-krb5-1.2.7-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-devel-1.2.7-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.2.7-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.2.7-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.2.7-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"telnet-client-krb5-1.2.7-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"telnet-server-krb5-1.2.7-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"krb5-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2002-0036", value:TRUE);
 set_kb_item(name:"CVE-2003-0028", value:TRUE);
 set_kb_item(name:"CVE-2003-0058", value:TRUE);
 set_kb_item(name:"CVE-2003-0059", value:TRUE);
 set_kb_item(name:"CVE-2003-0072", value:TRUE);
 set_kb_item(name:"CVE-2003-0082", value:TRUE);
 set_kb_item(name:"CVE-2003-0138", value:TRUE);
 set_kb_item(name:"CVE-2003-0139", value:TRUE);
}
exit(0, "Host is not affected");
