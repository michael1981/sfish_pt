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
 script_id(40375);
 script_version("$Revision: 1.2 $");
 script_name(english: "VMSA-2008-0004");
 script_set_attribute(attribute: "synopsis", value: 
"Low: Updated e2fsprogs service console package");
 script_set_attribute(attribute: "description", value: 
'
Updated e2fsprogs package address multiple integer overflow flaws

Thanks to Rafal Wojtczuk of McAfee Avert Research for identifying and
reporting this issue.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2007-5497 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000010.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000010.html');
script_end_attributes();
 script_cve_id("CVE-2007-5497");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-03-03");
report = '';
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1003517"))
  report = strcat(report, 'Patch ESX-1003517 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1003523"))
  report = strcat(report, 'Patch ESX-1003523 for ESX 3.0.2 needs to be installed
');
if (report)
{
 security_warning(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
