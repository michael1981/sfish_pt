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
 script_id(40378);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2008-0009");
 script_set_attribute(attribute: "synopsis", value: 
"Updates to VMware ESX resolve critical security issues");
 script_set_attribute(attribute: "description", value: 
'
a. VMware Tools Local Privilege Escalation on Windows-based guest OS

The VMware Tools Package provides support required for shared folders
(HGFS) and other features.

An input validation error is present in the Windows-based VMware
HGFS.sys driver.   Exploitation of this flaw might result in
arbitrary code execution on the guest system by an unprivileged
guest user.  It doesn\'t matter on what host the Windows guest OS
is running, as this is a guest driver vulnerability and not a
vulnerability on the host.

The HGFS.sys driver is present in the guest operating system if the
VMware Tools package is loaded.  Even if the host has HGFS disabled
and has no shared folders, Windows-based guests may be affected. This
is regardless if a host supports HGFS.

This issue could be mitigated by removing the VMware Tools package
from Windows based guests.  However this is not recommended as it
would impact usability of the product.

NOTE: Installing the new hosted release or ESX patches will not
remediate the issue.  The VMware Tools packages will need
to be updated on each Windows-based guest followed by a
reboot of the guest system.

VMware would like to thank iDefense and Stephen Fewer of Harmony
Security for reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2007-5671 to this issue.


b. Privilege escalation on ESX or Linux based hosted operating systems

This update fixes a security issue related to local exploitation of
an untrusted library path vulnerability in vmware-authd. In order to
exploit this vulnerability, an attacker must have local access and
the ability to execute the set-uid vmware-authd binary on an affected
system. Exploitation of this flaw might result in arbitrary code
execution on the Linux host system by an unprivileged user.

VMware would like to thank iDefense for reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2008-0967 to this issue.

c. Openwsman Invalid Content-Length Vulnerability

Openwsman is a system management platform that implements the Web
Services Management protocol (WS-Management). It is installed and
running by default. It is used in the VMware Management Service
Console and in ESXi.

The openwsman management service on ESX 3.5 and ESXi 3.5 is vulnerable
to a privilege escalation vulnerability, which may allow users with
non-privileged ESX or Virtual Center accounts to gain root privileges.

To exploit this vulnerability, an attacker would need a local ESX
account or a VirtualCenter account with the Host.Cim.CimInteraction
permission.

Systems with no local ESX accounts and no VirtualCenter accounts with
the Host.Cim.CimInteraction permission are not vulnerable.

This vulnerability cannot be exploited by users without valid login
credentials.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000022.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000022.html');
script_end_attributes();
 script_cve_id("CVE-2006-1721", "CVE-2007-4772", "CVE-2007-5378", "CVE-2007-5671", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0553", "CVE-2008-0888", "CVE-2008-0948", "CVE-2008-0967", "CVE-2008-2097", "CVE-2008-2100");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-06-04");
report = '';
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1004186"))
  report = strcat(report, 'Patch ESX-1004186 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1004728"))
  report = strcat(report, 'Patch ESX-1004728 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1004725"))
  report = strcat(report, 'Patch ESX-1004725 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1004721"))
  report = strcat(report, 'Patch ESX-1004721 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1004723"))
  report = strcat(report, 'Patch ESX-1004723 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1004190"))
  report = strcat(report, 'Patch ESX-1004190 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1004189"))
  report = strcat(report, 'Patch ESX-1004189 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 2.5.5", patch: "8"))
  report = strcat(report, 'Patch 8 for ESX 2.5.5 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1004727"))
  report = strcat(report, 'Patch ESX-1004727 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1004821"))
  report = strcat(report, 'Patch ESX-1004821 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1004216"))
  report = strcat(report, 'Patch ESX-1004216 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1004726"))
  report = strcat(report, 'Patch ESX-1004726 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1004722"))
  report = strcat(report, 'Patch ESX-1004722 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1004724"))
  report = strcat(report, 'Patch ESX-1004724 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1004719"))
  report = strcat(report, 'Patch ESX-1004719 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1004219"))
  report = strcat(report, 'Patch ESX-1004219 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 2.5.4", patch: "19"))
  report = strcat(report, 'Patch 19 for ESX 2.5.4 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200805515-SG"))
  report = strcat(report, 'Patch ESX350-200805515-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200805508-SG"))
  report = strcat(report, 'Patch ESX350-200805508-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200805504-SG"))
  report = strcat(report, 'Patch ESX350-200805504-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200805506-SG"))
  report = strcat(report, 'Patch ESX350-200805506-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200805505-SG"))
  report = strcat(report, 'Patch ESX350-200805505-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200805507-SG"))
  report = strcat(report, 'Patch ESX350-200805507-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
