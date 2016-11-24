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
 script_id(40391);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2009-0006");
 script_set_attribute(attribute: "synopsis", value: 
"VMware patches for ESX resolve a critical security vulnerability");
 script_set_attribute(attribute: "description", value: 
'
a. Host code execution vulnerability from a guest operating system

A critical vulnerability in the virtual machine display function
might allow a guest operating system to run code on the host.

This issue is different from the vulnerability in a guest virtual
device driver reported in VMware security advisory VMSA-2009-0005
on 2009-04-03. That vulnerability can cause a potential denial of
service and is identified by CVE-2008-4916.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2009-1244 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2009/000055.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2009/000055.html');
script_end_attributes();
 script_cve_id("CVE-2009-1244");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2009-04-10");
report = '';
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200904403-SG"))
  report = strcat(report, 'Patch ESX303-200904403-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1008421"))
  report = strcat(report, 'Patch ESX-1008421 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200904201-SG"))
  report = strcat(report, 'Patch ESX350-200904201-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_warning(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
