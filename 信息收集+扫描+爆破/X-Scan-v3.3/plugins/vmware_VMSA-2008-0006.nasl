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
 script_id(40376);
 script_version("$Revision: 1.2 $");
 script_name(english: "VMSA-2008-0006");
 script_set_attribute(attribute: "synopsis", value: 
"Updated libxml2 service console package");
 script_set_attribute(attribute: "description", value: 
'
Updated libxml2 package to address a denial of service flaw.

Thanks to the Google security team for identifying and reporting
this issue.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2007-6284 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000011.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000011.html');
script_end_attributes();
 script_cve_id("CVE-2007-6284");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-03-28");
report = '';
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1003521"))
  report = strcat(report, 'Patch ESX-1003521 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 2.5.5", patch: "6"))
  report = strcat(report, 'Patch 6 for ESX 2.5.5 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1003528"))
  report = strcat(report, 'Patch ESX-1003528 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 2.5.4", patch: "17"))
  report = strcat(report, 'Patch 17 for ESX 2.5.4 needs to be installed
');
if (report)
{
 security_warning(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
