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
 script_id(40377);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2008-0007");
 script_set_attribute(attribute: "synopsis", value: 
"Moderate Updated Service Console packages pcre,
net-snmp, and OpenPegasus");
 script_set_attribute(attribute: "description", value: 
'
a. Updated pcre Service Console package addresses several security issues

The pcre package contains the Perl-Compatible Regular Expression library.
pcre is used by various Service Console utilities.

Several security issues were discovered in the way PCRE handles regular
expressions. If an application linked against PCRE parsed a malicious
regular expression, it may have been possible to run arbitrary code as
the user running the application.

VMware would like to thank Ludwig Nussel for reporting these issues.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2006-7228 and CVE-2007-1660 to these issues.

RPM Updated:
pcre-3.9-10.4.i386.rpm

VMware ESX 3.5 patch ESX350-200803214-UG(pcre, net-snmp)

VMware ESX 3.0.2 patch ESX-1004217(pcre)
VMware ESX 3.0.1 patch ESX-1004187(pcre)

b. Updated net-snmp Service Console package addresses denial of service

net-snmp is an implementation of the Simple Network Management
Protocol (SNMP).  SNMP is used by network management systems to
monitor hosts.  By default ESX has this service enabled and its ports
open on the ESX firewall.

A flaw was discovered in the way net-snmp handled certain requests. A
remote attacker who can connect to the snmpd UDP port could send a
malicious packet causing snmpd to crash, resulting in a denial of
service.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2007-5846 to this issue.

RPM Updated:
net-snmp-5.0.9-2.30E.23.i386.rpm
net-snmp-libs-5.0.9-2.30E.23.i386.rpm
net-snmp-utils-5.0.9-2.30E.23.i386.rpm

VMware ESX 3.5 patch ESX350-200803214-UG(pcre, net-snmp)

VMware ESX 3.0.2 patch ESX-1004218 (net-snmp)
VMware ESX 3.0.1 patch ESX-1004188 (net-snmp)

c. Updated OpenPegasus Service Console package fixes overflow condition

OpenPegasus is a CIM (Common Information Model) and Web-Based Enterprise
Management (WBEM) broker.  These protocols are used by network management
systems to monitor and control hosts.  By default ESX has this service
enabled and its ports open on the ESX firewall.

A flaw was discovered in the OpenPegasus CIM management server that
might allow remote attackers to execute arbitrary code.  OpenPegasus
when compiled to use PAM and without PEGASUS_USE_PAM_STANDALONE_PROC
defined, has a stack-based buffer overflow condition.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2008-0003 to this issue.

RPMS updated:
cim-smwg-1.0-release-606113.i386.rpm
pegasus-2.5-release-606113.i386.rpm

VMware ESX 3.5   patch ESX350-200803201-UG(OpenPegasus)
VMware ESX 3.0.2 patch ESX-1004213(OpenPegasus)
VMware ESX 3.0.1 patch ESX-1004184(OpenPegasus)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000019.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000019.html');
script_end_attributes();
 script_cve_id("CVE-2006-7228", "CVE-2007-1660", "CVE-2007-5846", "CVE-2008-0003");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-04-15");
report = '';
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1004184"))
  report = strcat(report, 'Patch ESX-1004184 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1004187"))
  report = strcat(report, 'Patch ESX-1004187 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1004188"))
  report = strcat(report, 'Patch ESX-1004188 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1004213"))
  report = strcat(report, 'Patch ESX-1004213 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1004217"))
  report = strcat(report, 'Patch ESX-1004217 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1004218"))
  report = strcat(report, 'Patch ESX-1004218 for ESX 3.0.2 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
