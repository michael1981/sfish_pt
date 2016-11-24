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
 script_id(40387);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2009-0001");
 script_set_attribute(attribute: "synopsis", value: 
"ESX patches address an issue loading corrupt virtual
disks and update Service Console packages");
 script_set_attribute(attribute: "description", value: 
'
a. Loading a corrupt delta disk may cause ESX to crash

If the VMDK delta disk of a snapshot is corrupt, an ESX host might
crash when the corrupted disk is loaded.  VMDK delta files exist
for virtual machines with one or more snapshots. This change ensures
that a corrupt VMDK delta file cannot be used to crash ESX hosts.

A corrupt VMDK delta disk, or virtual machine would have to be loaded
by an administrator.

VMware would like to thank Craig Marshall for reporting this issue.

The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2008-4914 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2009/000052.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2009/000052.html');
script_end_attributes();
 script_cve_id("CVE-2008-4225", "CVE-2008-4226", "CVE-2008-4309", "CVE-2008-4914");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2009-01-30");
report = '';
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200901405-SG"))
  report = strcat(report, 'Patch ESX303-200901405-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200901406-SG"))
  report = strcat(report, 'Patch ESX303-200901406-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 2.5.5", patch: "12"))
  report = strcat(report, 'Patch 12 for ESX 2.5.5 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1007673"))
  report = strcat(report, 'Patch ESX-1007673 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1007674"))
  report = strcat(report, 'Patch ESX-1007674 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200901401-SG"))
  report = strcat(report, 'Patch ESX350-200901401-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200901409-SG"))
  report = strcat(report, 'Patch ESX350-200901409-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200901410-SG"))
  report = strcat(report, 'Patch ESX350-200901410-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
