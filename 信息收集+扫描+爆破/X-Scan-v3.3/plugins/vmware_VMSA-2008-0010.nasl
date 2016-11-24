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
 script_id(40379);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2008-0010");
 script_set_attribute(attribute: "synopsis", value: 
"Updated Tomcat and Java JRE packages for VMware
ESX 3.5 and VirtualCenter");
 script_set_attribute(attribute: "description", value: 
'
ESX patches and updates for VirtualCenter fix the following
application vulnerabilities.

a. Tomcat Server Security Update

The ESX patches and the updates for VirtualCenter update the
Tomcat Server package to version 5.5.26, which addresses multiple
security issues that existed in earlier releases of Tomcat Server.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2007-5333, CVE-2007-5342, CVE-2007-5461,
CVE-2007-6286 to the security issues fixed in Tomcat 5.5.26.

b. JRE Security Update

The ESX patches and the updates for VirtualCenter update the JRE
package to version 1.5.0_15, which addresses multiple security
issues that existed in earlier releases of JRE.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2008-1185, CVE-2008-1186, CVE-2008-1187,
CVE-2008-1188, CVE-2008-1189, CVE-2008-1190, CVE-2008-1191,
CVE-2008-1192, CVE-2008-1193, CVE-2008-1194, CVE-2008-1195,
CVE-2008-1196, CVE-2008-0657, CVE-2007-5689, CVE-2007-5232,
CVE-2007-5236, CVE-2007-5237, CVE-2007-5238, CVE-2007-5239,
CVE-2007-5240, CVE-2007-5274 to the security issues fixed in
JRE 1.5.0_12, JRE 1.5.0_13, JRE 1.5.0_14, JRE 1.5.0_15.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000031.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000031.html');
script_end_attributes();
 script_cve_id("CVE-2007-5232", "CVE-2007-5236", "CVE-2007-5237", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5274", "CVE-2007-5333", "CVE-2007-5342", "CVE-2007-5461", "CVE-2007-5689", "CVE-2007-6286", "CVE-2008-0657", "CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-06-16");
report = '';
if (esx_check(ver: "ESX 3.0.3", patch: "ESX303-200808407-SG"))
  report = strcat(report, 'Patch ESX303-200808407-SG for ESX 3.0.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1004823"))
  report = strcat(report, 'Patch ESX-1004823 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1006360"))
  report = strcat(report, 'Patch ESX-1006360 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200806404-SG"))
  report = strcat(report, 'Patch ESX350-200806404-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
