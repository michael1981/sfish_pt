
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32048);
 script_version ("$Revision: 1.7 $");
 script_name(english: "SuSE Security Update:  Security update for clamav (clamav-5200)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch clamav-5200");
 script_set_attribute(attribute: "description", value: "This version upgrade of ClamAV to 0.93 fixes a long list of
vulnerabilities. These vulnerabilities can lead to remote
code execution, bypassing the scanning engine, remote
denial-of-service, local file overwrite. (CVE-2008-1837,
CVE-2008-1836, CVE-2008-1835, CVE-2008-1833, CVE-2008-1387,
CVE-2008-1100, CVE-2008-0314, CVE-2007-6595, CVE-2007-6596)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch clamav-5200");
script_end_attributes();

script_cve_id("CVE-2007-6595", "CVE-2007-6596", "CVE-2008-0314", "CVE-2008-1100", "CVE-2008-1387", "CVE-2008-1833", "CVE-2008-1835", "CVE-2008-1836", "CVE-2008-1837");
script_summary(english: "Check for the clamav-5200 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"clamav-0.93-0.6", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
