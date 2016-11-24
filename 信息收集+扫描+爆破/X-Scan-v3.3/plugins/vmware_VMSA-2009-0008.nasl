#
# (C) Tenable Network Security, Inc.
#
# The text of this plugin is (C) VMware Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);

if ( NASL_LEVEL < 3000 ) exit(0);

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40393);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2009-0008");
 script_set_attribute(attribute: "synopsis", value: 
"ESX Service Console update for krb5");
 script_set_attribute(attribute: "description", value: 
'
a. Service Console package krb5 update

Kerberos is a network authentication protocol. It is designed to
provide strong authentication for client/server applications by
using secret-key cryptography.

An input validation flaw in the asn1_decode_generaltime function in
MIT Kerberos 5 before 1.6.4 allows remote attackers to cause a
denial of service or possibly execute arbitrary code via vectors
involving an invalid DER encoding that triggers a free of an
uninitialized pointer.

A remote attacker could use this flaw to crash a network service
using the MIT Kerberos library, such as kadmind or krb5kdc, by
causing it to dereference or free an uninitialized pointer or,
possibly, execute arbitrary code with the privileges of the user
running the service.

NOTE: ESX by default is unaffected by this issue, the daemons
kadmind and krb5kdc are not installed in ESX.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2009-0846 to this issue.

In addition the ESX 4.0 Service Console krb5 package was also
updated for CVE-2009-0845, and CVE-2009-0844 and RHBA-2009-0135.

MIT Kerberos versions 5 1.5 through 1.6.3 might allow remote
attackers to cause a denial of service by using invalid
ContextFlags data in the reqFlags field in a negTokenInit token.

The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-0845 to this issue.

MIT Kerberos 5 before version 1.6.4 might allow remote attackers to
cause a denial of service or possibly execute arbitrary code by
using vectors involving an invalid DER encoding that triggers a
free of an uninitialized pointer.

The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-0846 to this issue.

For ESX 4.0, 3.5, 3.0.3 the Service Console package pam_krb5 has
also been upgraded.  For details on the non-security issues that
this upgrade addresses, refer to the respective KB article listed
in section 4 below.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2009/000063.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2009/000063.html');
script_end_attributes();
 script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2009-06-30");
report = '';
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200908403-SG"))
  report = strcat(report, 'Patch ESX303-200908403-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 2.5.5", patch: "14"))
  report = strcat(report, 'Patch 14 for ESX 2.5.5 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200906407-SG"))
  report = strcat(report, 'Patch ESX350-200906407-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
