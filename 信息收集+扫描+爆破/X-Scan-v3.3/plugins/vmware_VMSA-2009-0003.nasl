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
 script_id(40388);
 script_version("$Revision: 1.2 $");
 script_name(english: "VMSA-2009-0003");
 script_set_attribute(attribute: "synopsis", value: 
"ESX 2.5.5 patch 12 updates service console package ed");
 script_set_attribute(attribute: "description", value: 
'
a. Updated ESX patch updates Service Console package ed

ed is a line-oriented text editor, used to create, display, and
modify text files (both interactively and via shell scripts).

A heap-based buffer overflow was discovered in the way ed, the GNU
line editor, processed long file names. An attacker could create a
file with a specially-crafted name that could possibly execute an
arbitrary code when opened in the ed editor.

The Common Vulnerabilities and Exposures Project (cve.mitre.org)
has assigned the name CVE-2008-3916 to this issue.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2009/000051.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2009/000051.html');
script_end_attributes();
 script_cve_id("CVE-2008-3916");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2009-01-26");
report = '';
if (esx_check(ver: "ESX 2.5.5", patch: "12"))
  report = strcat(report, 'Patch 12 for ESX 2.5.5 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
