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
 script_id(40373);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2008-0002");
 script_set_attribute(attribute: "synopsis", value: 
"Low severity security update for VirtualCenter
and ESX");
 script_set_attribute(attribute: "description", value: 
'
Updated VirtualCenter fixes the following application vulnerabilities

a. Tomcat Server Security Update
This release of VirtualCenter Server updates the Tomcat Server
package from 5.5.17 to 5.5.25, which addresses multiple security
issues that existed in the earlier releases of Tomcat Server.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2005-2090, CVE-2006-7195, and CVE-2007-0450 to
these issues.

b. JRE Security Update
This release of VirtualCenter Server updates the JRE package from
1.5.0_7 to 1.5.0_12, which addresses a security issue that existed in
the earlier release of JRE.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2007-3004 to this issue.

NOTE: These vulnerabilities can be exploited remotely only if the
attacker has access to the service console network.

Security best practices provided by VMware recommend that the
service console be isolated from the VM network. Please see
http://www.vmware.com/resources/techresources/726 for more
information on VMware security best practices.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000013.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000013.html');
script_end_attributes();
 script_cve_id("CVE-2005-2090", "CVE-2006-7195");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-01-07");
report = '';
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1003176"))
  report = strcat(report, 'Patch ESX-1003176 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1002434"))
  report = strcat(report, 'Patch ESX-1002434 for ESX 3.0.2 needs to be installed
');
if (report)
{
 security_warning(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
