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
 script_id(40381);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2008-0013");
 script_set_attribute(attribute: "synopsis", value: 
"Updated ESX packages for OpenSSL, net-snmp, perl");
 script_set_attribute(attribute: "description", value: 
'
I Security Issues

a. OpenSSL Binaries Updated

This fix updates the third party OpenSSL library.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2007-3108 and CVE-2007-5135 to the issues
addressed by this update.

II Service Console rpm updates

a. net-snmp Security update

This fix upgrades the service console rpm for net-snmp to version
net-snmp-5.0.9-2.30E.24.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000036.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000036.html');
script_end_attributes();
 script_cve_id("CVE-2007-3108", "CVE-2007-5135", "CVE-2008-0960", "CVE-2008-1927", "CVE-2008-2292");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-08-12");
report = '';
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200808401-SG"))
  report = strcat(report, 'Patch ESX303-200808401-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200808402-SG"))
  report = strcat(report, 'Patch ESX303-200808402-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1005115"))
  report = strcat(report, 'Patch ESX-1005115 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1006030"))
  report = strcat(report, 'Patch ESX-1006030 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1006355"))
  report = strcat(report, 'Patch ESX-1006355 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1005116"))
  report = strcat(report, 'Patch ESX-1005116 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1006031"))
  report = strcat(report, 'Patch ESX-1006031 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1006037"))
  report = strcat(report, 'Patch ESX-1006037 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200808405-SG"))
  report = strcat(report, 'Patch ESX350-200808405-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200808406-SG"))
  report = strcat(report, 'Patch ESX350-200808406-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
