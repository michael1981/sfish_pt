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
 script_id(40386);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2008-0019");
 script_set_attribute(attribute: "synopsis", value: 
"VMware patches for ESX resolve a critical security issue and update bzip2");
 script_set_attribute(attribute: "description", value: 
'
a. Critical Memory corruption vulnerability

A memory corruption condition may occur in the virtual machine
hardware. A malicious request sent from the guest operating
system to the virtual hardware may cause the virtual hardware to
write to uncontrolled physical memory.

VMware would like to thank Andrew Honig of the Department of
Defense for reporting this issue.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2008-4917 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000048.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000048.html');
script_end_attributes();
 script_cve_id("CVE-2008-1372", "CVE-2008-4917");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-12-02");
report = '';
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200811404-SG"))
  report = strcat(report, 'Patch ESX303-200811404-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1006980"))
  report = strcat(report, 'Patch ESX-1006980 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1006982"))
  report = strcat(report, 'Patch ESX-1006982 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200811406-SG"))
  report = strcat(report, 'Patch ESX350-200811406-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200811401-SG"))
  report = strcat(report, 'Patch ESX350-200811401-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
