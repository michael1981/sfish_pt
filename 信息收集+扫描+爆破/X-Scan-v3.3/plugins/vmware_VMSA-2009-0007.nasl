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
 script_id(40392);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2009-0007");
 script_set_attribute(attribute: "synopsis", value: 
"VMware ESX patches resolve security issues");
 script_set_attribute(attribute: "description", value: 
'
a. VMware Descheduled Time Accounting driver vulnerability may cause a
denial of service in Windows based virtual machines.

The VMware Descheduled Time Accounting Service is an optional,
experimental service that provides improved guest operating system
accounting.

This patch fixes a denial of service vulnerability that could be
triggered in a virtual machine by an unprivileged, locally
logged-on user in the virtual machine.

Virtual machines are affected under the following conditions:

- The virtual machine is running a Windows operating system.

- The VMware Descheduled Time Accounting driver is installed
in the virtual machine. Note that this is an optional (non-
default) part of the VMware Tools installation.

- The VMware Descheduled Time Accounting Service is not running
in the virtual machine

The VMware Descheduled Time Accounting Service is no longer provided
in newer versions of VMware Tools, starting with the versions
released in Fusion 2.0.2 and ESX 4.0.

However, virtual machines migrated from vulnerable releases will
still be vulnerable if the three conditions listed above are met,
until their tools are upgraded.

Steps needed to remediate this vulnerability:

Guest systems on VMware Workstation, Player, ACE, Server, Fusion
- Install the new version of Workstation, Player, ACE, Server,
Fusion (see below for version information)
- Upgrade tools in the virtual machine (virtual machine users
will be prompted to upgrade).

Guest systems on ESX 3.5, ESXi 3.5, ESX 3.0.2, ESX 3.0.3
- Install the relevant patches (see below for patch identifiers)
- Manually upgrade tools in the virtual machine (virtual machine
users will not be prompted to upgrade).  Note the VI Client will
not show the VMware tools is out of date in the summary tab.
Please see http://tinyurl.com/27mpjo page 80 for details.

Guests systems on ESX 4.0 and ESXi 4.0 that have been migrated from
ESX 3.5, ESXi 3.5, and ESX 3.0.x
- Install/upgrade the new tools in the virtual machine (virtual
machine users will be prompted to upgrade).

If the Descheduled Time Accounting driver was installed, the tools
upgrade will result in an updated driver for Workstation, Player,
ACE, Server, ESX 3.0.2, ESX 3.0.3, ESX 3.5, ESXi 3.5. For Fusion,
ESX 4.0, and ESXi 4.0 the tools upgrade will result in the removal
of the driver.

VMware would like to thank Nikita Tarakanov for reporting this
issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2009-1805 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2009/000057.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2009/000057.html');
script_end_attributes();
 script_cve_id("CVE-2008-1382", "CVE-2009-0040", "CVE-2009-1805");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2009-05-28");
report = '';
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200905401-SG"))
  report = strcat(report, 'Patch ESX303-200905401-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 2.5.5", patch: "13"))
  report = strcat(report, 'Patch 13 for ESX 2.5.5 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1008420"))
  report = strcat(report, 'Patch ESX-1008420 for ESX 3.0.2 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
