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
 script_id(40383);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2008-0016");
 script_set_attribute(attribute: "synopsis", value: 
"VMware patches for ESX resolve multiple security
issues");
 script_set_attribute(attribute: "description", value: 
'
a.  Privilege escalation on 64-bit guest operating systems

VMware products emulate hardware functions, like CPU, Memory, and
IO.  

A flaw in VMware\'s CPU hardware emulation could allow the
virtual CPU to jump to an incorrect memory address. Exploitation of
this issue on the guest operating system does not lead to a
compromise of the host system but could lead to a privilege
escalation on guest operating system.  An attacker would need to
have a user account on the guest operating system.

Affected
64-bit Windows and 64-bit FreeBSD guest operating systems and
possibly other 64-bit operating systems. The issue does not
affect the 64-bit versions of Linux guest operating systems.

VMware would like to thank Derek Soeder for discovering
this issue and working with us on its remediation.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2008-4279 this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000044.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000044.html');
script_end_attributes();
 script_cve_id("CVE-2008-3103", "CVE-2008-3104", "CVE-2008-3105", "CVE-2008-3106", "CVE-2008-3107", "CVE-2008-3108", "CVE-2008-3109", "CVE-2008-3110", "CVE-2008-3111", "CVE-2008-3112", "CVE-2008-3113", "CVE-2008-3114", "CVE-2008-3115", "CVE-2008-4278", "CVE-2008-4279");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-10-03");
report = '';
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200809401-SG"))
  report = strcat(report, 'Patch ESX303-200809401-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1006678"))
  report = strcat(report, 'Patch ESX-1006678 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1006361"))
  report = strcat(report, 'Patch ESX-1006361 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200809404-SG"))
  report = strcat(report, 'Patch ESX350-200809404-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
