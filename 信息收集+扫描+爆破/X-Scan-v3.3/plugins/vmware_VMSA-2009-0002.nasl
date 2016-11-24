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
 script_id(42178);
 script_version("$Revision: 1.1 $");
 script_name(english: "VMSA-2009-0002");
 script_set_attribute(attribute: "synopsis", value: 
"VirtualCenter Update 4 and ESX patch update Tomcat
to version 5.5.27");
 script_set_attribute(attribute: "description", value: 
'
a. Update for VirtualCenter and ESX patch update Apache Tomcat version
to 5.5.27

Update for VirtualCenter and ESX patch update the Tomcat package to
version 5.5.27 which addresses multiple security issues that existed
in the previous version of Apache Tomcat.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2008-1232, CVE-2008-1947 and
CVE-2008-2370 to these issues.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2009/000068.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2009/000068.html');
script_end_attributes();
 script_cve_id("CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2370");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2009-02-23");
report = '';
if (esx_check(ver: "ESX 3.5.0", patch: "ESX350-200910403-SG"))
  report = strcat(report, 'Patch ESX350-200910403-SG for ESX 3.5.0 needs to be installed
');
if (report)
{
 security_warning(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
