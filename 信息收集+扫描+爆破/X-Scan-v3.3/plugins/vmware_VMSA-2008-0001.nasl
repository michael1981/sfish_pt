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
 script_id(40372);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2008-0001");
 script_set_attribute(attribute: "synopsis", value: 
"Moderate OpenPegasus PAM Authentication Buffer
Overflow and updated service console packages");
 script_set_attribute(attribute: "description", value: 
'
I   Service Console package security updates

a. OpenPegasus PAM Authentication Buffer Overflow

Alexander Sotirov from VMware Security Research discovered a
buffer overflow vulnerability in the OpenPegasus Management server.
This flaw could be exploited by a malicious remote user on the
service console network to gain root access to the service console.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2007-5360 to this issue.

RPM Updated: pegasus-2.5-552927
VM Shutdown: No
Host Reboot: No
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000004.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000004.html');
script_end_attributes();
 script_cve_id("CVE-2007-3108", "CVE-2007-4572", "CVE-2007-5116", "CVE-2007-5135", "CVE-2007-5191", "CVE-2007-5360", "CVE-2007-5398");

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
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1002962"))
  report = strcat(report, 'Patch ESX-1002962 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1002963"))
  report = strcat(report, 'Patch ESX-1002963 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1002964"))
  report = strcat(report, 'Patch ESX-1002964 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1002968"))
  report = strcat(report, 'Patch ESX-1002968 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1002972"))
  report = strcat(report, 'Patch ESX-1002972 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1003176"))
  report = strcat(report, 'Patch ESX-1003176 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 2.5.5", patch: "3"))
  report = strcat(report, 'Patch 3 for ESX 2.5.5 needs to be installed
');
if (esx_check(ver: "ESX 2.5.5", patch: "14"))
  report = strcat(report, 'Patch 14 for ESX 2.5.5 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1002969"))
  report = strcat(report, 'Patch ESX-1002969 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1002970"))
  report = strcat(report, 'Patch ESX-1002970 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1002971"))
  report = strcat(report, 'Patch ESX-1002971 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1002975"))
  report = strcat(report, 'Patch ESX-1002975 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1002976"))
  report = strcat(report, 'Patch ESX-1002976 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200712402-SG"))
  report = strcat(report, 'Patch ESX350-200712402-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200712403-SG"))
  report = strcat(report, 'Patch ESX350-200712403-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200712404-SG"))
  report = strcat(report, 'Patch ESX350-200712404-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
