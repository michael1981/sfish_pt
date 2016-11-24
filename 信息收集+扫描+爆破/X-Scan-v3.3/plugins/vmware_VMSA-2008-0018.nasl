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
 script_id(40385);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2008-0018");
 script_set_attribute(attribute: "synopsis", value: 
"VMware patches for ESX resolve two security issues");
 script_set_attribute(attribute: "description", value: 
'
a. A privilege escalation on 32-bit and 64-bit guest operating systems

VMware products emulate hardware functions and create the
possibility to run guest operating systems.

A flaw in the CPU hardware emulation might allow the virtual CPU to
incorrectly handle the Trap flag. Exploitation of this flaw might
lead to a privilege escalation on guest operating systems.  An
attacker needs a user account on the guest operating system and
have the ability to run applications.

VMware would like to thank Derek Soeder for discovering
this issue and working with us on its remediation.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2008-4915 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000042.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000042.html');
script_end_attributes();
 script_cve_id("CVE-2008-4281", "CVE-2008-4915");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-11-06");
report = '';
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1006680"))
  report = strcat(report, 'Patch ESX-1006680 for ESX 3.0.2 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
