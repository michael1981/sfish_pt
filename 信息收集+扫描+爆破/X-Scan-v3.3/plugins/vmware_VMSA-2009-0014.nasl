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
 script_id(42179);
 script_version("$Revision: 1.1 $");
 script_name(english: "VMSA-2009-0014");
 script_set_attribute(attribute: "synopsis", value: 
"VMware ESX patches for DHCP, Service Console kernel,
and JRE resolve multiple security issues");
 script_set_attribute(attribute: "description", value: 
'
a. Service Console update for DHCP and third party library update
for DHCP client.

DHCP is an Internet-standard protocol by which a computer can be
connected to a local network, ask to be given configuration
information, and receive from a server enough information to
configure itself as a member of that network.

A stack-based buffer overflow in the script_write_params method in
ISC DHCP dhclient allows remote DHCP servers to execute arbitrary
code via a crafted subnet-mask option.

The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-0692 to this issue.

An insecure temporary file use flaw was discovered in the DHCP
daemon\'s init script (&quot;/etc/init.d/dhcpd&quot;). A local attacker could
use this flaw to overwrite an arbitrary file with the output of the
&quot;dhcpd -t&quot; command via a symbolic link attack, if a system
administrator executed the DHCP init script with the &quot;configtest&quot;,
&quot;restart&quot;, or &quot;reload&quot; option.

The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2009-1893 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2009/000067.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2009/000067.html');
script_end_attributes();
 script_cve_id("CVE-2007-6063", "CVE-2008-0598", "CVE-2008-2086", "CVE-2008-2136", "CVE-2008-2812", "CVE-2008-3275", "CVE-2008-3525", "CVE-2008-4210", "CVE-2008-5339", "CVE-2008-5340", "CVE-2008-5341", "CVE-2008-5342", "CVE-2008-5343", "CVE-2008-5344", "CVE-2008-5345", "CVE-2008-5346", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5355", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360", "CVE-2009-0692", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107", "CVE-2009-1893");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2009-10-16");
report = '';
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200910402-SG"))
  report = strcat(report, 'Patch ESX303-200910402-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200910406-SG"))
  report = strcat(report, 'Patch ESX350-200910406-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200910401-SG"))
  report = strcat(report, 'Patch ESX350-200910401-SG for ESX 3.5.0 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200910403-SG"))
  report = strcat(report, 'Patch ESX350-200910403-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
