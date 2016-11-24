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
 script_id(40390);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2009-0005");
 script_set_attribute(attribute: "synopsis", value: 
"VMware patches for ESX resolve multiple security issues");
 script_set_attribute(attribute: "description", value: 
'
a. Denial of service guest to host vulnerability in a virtual device

A vulnerability in a guest virtual device driver, could allow a
guest operating system to crash the host and consequently any
virtual machines on that host.

VMware would like to thank Andrew Honig of the Department of
Defense for reporting this issue.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2008-4916 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2009/000054.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2009/000054.html');
script_end_attributes();
 script_cve_id("CVE-2008-3761", "CVE-2008-4916", "CVE-2009-0177", "CVE-2009-0518", "CVE-2009-0908", "CVE-2009-0909", "CVE-2009-0910", "CVE-2009-1146", "CVE-2009-1147");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2009-04-03");
report = '';
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1006980"))
  report = strcat(report, 'Patch ESX-1006980 for ESX 3.0.2 needs to be installed
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
