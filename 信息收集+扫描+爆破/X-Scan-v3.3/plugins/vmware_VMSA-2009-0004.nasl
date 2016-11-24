#
# (C) Tenable Network Security, Inc.
#
# The text of this plugin is (C) VMware Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40389);
 script_version("$Revision: 1.2 $");
 script_name(english: "VMSA-2009-0004");
 script_set_attribute(attribute: "synopsis", value: 
"ESX Service Console updates for openssl, bind, and
vim");
 script_set_attribute(attribute: "description", value: 
'
a. Updated OpenSSL package for the Service Console fixes a
security issue.

OpenSSL 0.9.7a-33.24 and earlier does not properly check the return
value from the EVP_VerifyFinal function, which could allow a remote
attacker to bypass validation of the certificate chain via a
malformed SSL/TLS signature for DSA and ECDSA keys.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2008-5077 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2009/000058.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2009/000058.html');
script_end_attributes();
 script_cve_id("CVE-2007-2953", "CVE-2008-2712", "CVE-2008-3432", "CVE-2008-4101", "CVE-2008-5077", "CVE-2009-0025");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2009-03-31");
report = '';
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200903406-SG"))
  report = strcat(report, 'Patch ESX303-200903406-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200903405-SG"))
  report = strcat(report, 'Patch ESX303-200903405-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200903403-SG"))
  report = strcat(report, 'Patch ESX303-200903403-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 2.5.5", patch: "13"))
  report = strcat(report, 'Patch 13 for ESX 2.5.5 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1008409"))
  report = strcat(report, 'Patch ESX-1008409 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1008408"))
  report = strcat(report, 'Patch ESX-1008408 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1008406"))
  report = strcat(report, 'Patch ESX-1008406 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200904408-SG"))
  report = strcat(report, 'Patch ESX350-200904408-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200904407-SG"))
  report = strcat(report, 'Patch ESX350-200904407-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200904406-SG"))
  report = strcat(report, 'Patch ESX350-200904406-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
