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
 script_id(42289);
 script_version("$Revision: 1.1 $");
 script_name(english: "VMSA-2009-0015");
 script_set_attribute(attribute: "synopsis", value: 
"VMware hosted products and ESX patches resolve two
security issues");
 script_set_attribute(attribute: "description", value: 
'
a. Mishandled exception on page faults

An improper setting of the exception code on page faults may allow
for local privilege escalation on the guest operating system. This
vulnerability does not affect the host system.

VMware would like to thank Tavis Ormandy and Julien Tinnes of the
Google Security Team for reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2009-2267 to this issue.
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2009/000069.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2009/000069.html');
script_end_attributes();
 script_cve_id("CVE-2009-2267", "CVE-2009-3733");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2009-10-27");
report = '';
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200910401-SG"))
  report = strcat(report, 'Patch ESX350-200910401-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200901401-SG"))
  report = strcat(report, 'Patch ESX350-200901401-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
