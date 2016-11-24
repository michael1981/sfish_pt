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
 script_id(40380);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2008-0011");
 script_set_attribute(attribute: "synopsis", value: 
"Updated ESX service console packages for Samba
and vmnix");
 script_set_attribute(attribute: "description", value: 
'
I   Service Console rpm updates

a.  Security Update to Service Console Kernel

This fix upgrades service console kernel version to 2.4.21-57.EL.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2007-5001, CVE-2007-6151, CVE-2007-6206,
CVE-2008-0007, CVE-2008-1367, CVE-2008-1375, CVE-2006-4814, and
CVE-2008-1669 to the security issues fixed in kernel-2.4.21-57.EL.

b.  Samba Security Update

This fix upgrades the service console rpm samba to version
3.0.9-1.3E.15vmw

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2008-1105 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2008/000041.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2008/000041.html');
script_end_attributes();
 script_cve_id("CVE-2006-4814", "CVE-2007-5001", "CVE-2007-6151", "CVE-2007-6206", "CVE-2008-0007", "CVE-2008-1105", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1669");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2008-07-28");
report = '';
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1006028"))
  report = strcat(report, 'Patch ESX-1006028 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 2.5.5", patch: "10"))
  report = strcat(report, 'Patch 10 for ESX 2.5.5 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1006029"))
  report = strcat(report, 'Patch ESX-1006029 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 2.5.4", patch: "21"))
  report = strcat(report, 'Patch 21 for ESX 2.5.4 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
