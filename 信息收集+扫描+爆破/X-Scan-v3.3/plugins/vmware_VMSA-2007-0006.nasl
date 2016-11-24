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
 script_id(40370);
 script_version("$Revision: 1.3 $");
 script_name(english: "VMSA-2007-0006");
 script_set_attribute(attribute: "synopsis", value: 
"Critical security updates for all supported
versions of VMware ESX Server, VMware Server,
VMware Workstation, VMware ACE, and
VMware Player
");
 script_set_attribute(attribute: "description", value: 
'
Problems addressed by these patches:

I    Arbitrary code execution and denial of service vulnerabilities

This release fixes a security vulnerability that could allow a
guest operating system user with administrative privileges to cause
memory corruption in a host process, and thus potentially execute
arbitrary code on the host. (CVE-2007-4496)

This release fixes a denial of service vulnerability that could
allow a guest operating system to cause a host process to become
unresponsive or exit unexpectedly. (CVE-2007-4497)

Thanks to Rafal Wojtczvk of McAfee for identifying and reporting
these issues.

ESX
---
VMware ESX 3.0.1 Download Patch Bundle ESX-8258730
http://www.vmware.com/support/vi3/doc/esx-8258730-patch.html
md5sum a06d0e36e403b0fe6bc6fbc76220a86d

VMware ESX 3.0.0 Download Patch Bundle ESX-4809553
http://www.vmware.com/support/vi3/doc/esx-4809553-patch.html
md5sum cd363526aab5fa6c45bf2509cb5ae500

NOTE: ESX 3.0.0 is nearing its End-of-life (10/05/2007) users
should upgrade to at least 3.0.1 and preferably the newest
release available.

VMware ESX 2.5.4 upgrade to patch 10 (Build# 53326)
VMware ESX 2.5.3 upgrade to patch 13 (Build# 52488)
VMware ESX 2.1.3 upgrade to patch  8 (Build# 53228)
VMware ESX 2.0.2 upgrade to patch  8 (Build# 52650)

NOTE: ESX 3.0.2 is not affected by this issue

VI   ESX Service Console updates

a.   Service console package Samba, has been updated to address the
following issues:

Various bugs were found in NDR parsing, used to decode MS-RPC
requests in Samba. A remote attacker could have sent carefully
crafted requests causing a heap overflow, which may have led to the
ability to execute arbitrary code on the server. (CVE-2007-2446)

Unescaped user input parameters were being passed as arguments to
/bin/sh. A remote, authenticated, user could have triggered this
flaw and executed arbitrary code on the server. Additionally, this
flaw could be triggered by a remote unauthenticated user if Samba
was configured to use the non-default username map script option.
(CVE-2007-2447)

Thanks to the Samba developers, TippingPoint, and iDefense for
identifying and reporting these issues.
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
 script_set_attribute(attribute: 'see_also', value:
'http://lists.vmware.com/pipermail/security-announce/2007/000001.html');
script_set_attribute(attribute: "solution", value: 
'Apply the patch as indicated in the advisory :
http://lists.vmware.com/pipermail/security-announce/2007/000001.html');
script_end_attributes();
 script_cve_id("CVE-2004-0813", "CVE-2006-1174", "CVE-2006-3619", "CVE-2006-4146", "CVE-2006-4600", "CVE-2007-0061", "CVE-2007-0062", "CVE-2007-0063", "CVE-2007-0494", "CVE-2007-1716", "CVE-2007-1856", "CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2446", "CVE-2007-2447", "CVE-2007-2798", "CVE-2007-4059", "CVE-2007-4155", "CVE-2007-4496", "CVE-2007-4497");

 script_summary(english: "Check the installed VMware ESX packages");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "VMware ESX Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/VMware/version", "Host/VMware/esxupdate");
 exit(0);
}

include("vmware_esx_packages.inc");
init_esx_check(date: "2007-09-18");
report = '';
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-8258730"))
  report = strcat(report, 'Patch ESX-8258730 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1001213"))
  report = strcat(report, 'Patch ESX-1001213 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1001691"))
  report = strcat(report, 'Patch ESX-1001691 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1001723"))
  report = strcat(report, 'Patch ESX-1001723 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1001214"))
  report = strcat(report, 'Patch ESX-1001214 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1001692"))
  report = strcat(report, 'Patch ESX-1001692 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1001693"))
  report = strcat(report, 'Patch ESX-1001693 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-1001694"))
  report = strcat(report, 'Patch ESX-1001694 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-8253547"))
  report = strcat(report, 'Patch ESX-8253547 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 3.0.1", patch: "ESX-8567382"))
  report = strcat(report, 'Patch ESX-8567382 for ESX 3.0.1 needs to be installed
');
if (esx_check(ver: "ESX 2.1.3", patch: "8"))
  report = strcat(report, 'Patch 8 for ESX 2.1.3 needs to be installed
');
if (esx_check(ver: "ESX 2.5.3", patch: "13"))
  report = strcat(report, 'Patch 13 for ESX 2.5.3 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1001725"))
  report = strcat(report, 'Patch ESX-1001725 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1001731"))
  report = strcat(report, 'Patch ESX-1001731 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1001726"))
  report = strcat(report, 'Patch ESX-1001726 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1001727"))
  report = strcat(report, 'Patch ESX-1001727 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1001728"))
  report = strcat(report, 'Patch ESX-1001728 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1001729"))
  report = strcat(report, 'Patch ESX-1001729 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.2", patch: "ESX-1001730"))
  report = strcat(report, 'Patch ESX-1001730 for ESX 3.0.2 needs to be installed
');
if (esx_check(ver: "ESX 2.5.4", patch: "10"))
  report = strcat(report, 'Patch 10 for ESX 2.5.4 needs to be installed
');
if (esx_check(ver: "ESX 2.0.2", patch: "8"))
  report = strcat(report, 'Patch 8 for ESX 2.0.2 needs to be installed
');
if (esx_check(ver: "ESX 3.0.0", patch: "ESX-4809553"))
  report = strcat(report, 'Patch ESX-4809553 for ESX 3.0.0 needs to be installed
');
if (esx_check(ver: "ESX 3.0.0", patch: "ESX-1001204"))
  report = strcat(report, 'Patch ESX-1001204 for ESX 3.0.0 needs to be installed
');
if (esx_check(ver: "ESX 3.0.0", patch: "ESX-1001206"))
  report = strcat(report, 'Patch ESX-1001206 for ESX 3.0.0 needs to be installed
');
if (esx_check(ver: "ESX 3.0.0", patch: "ESX-1001212"))
  report = strcat(report, 'Patch ESX-1001212 for ESX 3.0.0 needs to be installed
');
if (esx_check(ver: "ESX 3.0.0", patch: "ESX-1001205"))
  report = strcat(report, 'Patch ESX-1001205 for ESX 3.0.0 needs to be installed
');
if (esx_check(ver: "ESX 3.0.0", patch: "ESX-1001207"))
  report = strcat(report, 'Patch ESX-1001207 for ESX 3.0.0 needs to be installed
');
if (esx_check(ver: "ESX 3.0.0", patch: "ESX-1001208"))
  report = strcat(report, 'Patch ESX-1001208 for ESX 3.0.0 needs to be installed
');
if (esx_check(ver: "ESX 3.0.0", patch: "ESX-1001209"))
  report = strcat(report, 'Patch ESX-1001209 for ESX 3.0.0 needs to be installed
');
if (esx_check(ver: "ESX 3.0.0", patch: "ESX-1001210"))
  report = strcat(report, 'Patch ESX-1001210 for ESX 3.0.0 needs to be installed
');
if (esx_check(ver: "ESX 3.0.0", patch: "ESX-1001211"))
  report = strcat(report, 'Patch ESX-1001211 for ESX 3.0.0 needs to be installed
');
if (report)
{
 security_hole(port: 0, extra: report);
 exit(0, report);
}
else
  exit(0, "Host if not affected");
