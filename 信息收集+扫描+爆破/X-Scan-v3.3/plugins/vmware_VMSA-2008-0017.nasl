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
 script_id(40384);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2008-0017");
 script_set_attribute(attribute: "synopsis", value: 
"Updated ESX packages for libxml2, ucd-snmp, libtiff");
 script_set_attribute(attribute: "description", value: 
'
a. Updated ESX Service Console package libxml2

A denial of service flaw was found in the way libxml2 processes
certain content. If an application that is linked against
libxml2 processes malformed XML content, the XML content might
cause the application to stop responding.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2008-3281 to this issue.

Additionally the following was also fixed, but was missing in the
security advisory.

A heap-based buffer overflow flaw was found in the way libxml2
handled long XML entity names. If an application linked against
libxml2 processed untrusted malformed XML content, it could cause
the application to crash or, possibly, execute arbitrary code.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2008-3529 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000047.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000047.html');
script_end_attributes();
 script_cve_id("CVE-2008-0960", "CVE-2008-2327", "CVE-2008-3281", "CVE-2008-3529");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-10-31");
report = '';
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200810503-SG"))
  report = strcat(report, 'Patch ESX303-200810503-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 2.5.5", patch: "10"))
  report = strcat(report, 'Patch 10 for ESX 2.5.5 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1006968"))
  report = strcat(report, 'Patch ESX-1006968 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 2.5.4", patch: "21"))
  report = strcat(report, 'Patch 21 for ESX 2.5.4 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
