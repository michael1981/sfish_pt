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
 script_id(40382);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2008-0014");
 script_set_attribute(attribute: "synopsis", value: 
"Updates to VMware Workstation, VMware Player,
VMware ACE, VMware Server, VMware ESX, VMware VCB
address information disclosure, privilege escalation
and other security issues.");
 script_set_attribute(attribute: "description", value: 
'
I Security Issues

a. Setting ActiveX killbit

Starting from this release, VMware has set the killbit on its
ActiveX controls. Setting the killbit ensures that ActiveX
controls cannot run in Internet Explorer (IE), and avoids
security issues involving ActiveX controls in IE. See the
Microsoft KB article 240797 and the related references on this
topic.

Security vulnerabilities have been reported for ActiveX controls
provided by VMware when run in IE. Under specific circumstances,
exploitation of these ActiveX controls might result in denial-of-
service or can allow running of arbitrary code when the user
browses a malicious Web site or opens a malicious file in IE
browser. An attempt to run unsafe ActiveX controls in IE might
result in pop-up windows warning the user.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000040.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000040.html');
script_end_attributes();
 script_cve_id("CVE-2007-5269", "CVE-2007-5438", "CVE-2007-5503", "CVE-2008-1447", "CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808", "CVE-2008-2101", "CVE-2008-3691", "CVE-2008-3692", "CVE-2008-3693", "CVE-2008-3694", "CVE-2008-3695", "CVE-2008-3696", "CVE-2008-3697", "CVE-2008-3698");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-08-29");
report = '';
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200808404-SG"))
  report = strcat(report, 'Patch ESX303-200808404-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200808403-SG"))
  report = strcat(report, 'Patch ESX303-200808403-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200808406-SG"))
  report = strcat(report, 'Patch ESX303-200808406-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1005108"))
  report = strcat(report, 'Patch ESX-1005108 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1005112"))
  report = strcat(report, 'Patch ESX-1005112 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1005111"))
  report = strcat(report, 'Patch ESX-1005111 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1004823"))
  report = strcat(report, 'Patch ESX-1004823 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1005117"))
  report = strcat(report, 'Patch ESX-1005117 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 2.5.5", patch: "10"))
  report = strcat(report, 'Patch 10 for ESX 2.5.5 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1005109"))
  report = strcat(report, 'Patch ESX-1005109 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1005113"))
  report = strcat(report, 'Patch ESX-1005113 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1005114"))
  report = strcat(report, 'Patch ESX-1005114 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 2.5.4", patch: "20"))
  report = strcat(report, 'Patch 20 for ESX 2.5.4 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200808409-SG"))
  report = strcat(report, 'Patch ESX350-200808409-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
