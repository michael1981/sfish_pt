
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41099);
 script_version("$Revision: 1.2 $");
 script_name(english: "SuSE9 Security Update:  Security update for gzip (11220)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 11220");
 script_set_attribute(attribute: "description", value: 'Several security issues with gzip have been found that can
be exploited to compromise the system in conjunction with
other programs while processing malformed archive files. The
vulnerabilities have been tracked by Mitre CVE-2006-4334,
CVE-2006-4335, CVE-2006-4336, CVE-2006-4337 and
CVE-2006-4338.
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch 11220");
script_end_attributes();

script_cve_id("CVE-2006-4334","CVE-2006-4335","CVE-2006-4336","CVE-2006-4337","CVE-2006-4338");
script_summary(english: "Check for the security advisory #11220");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gzip-1.3.5-136.13", release:"SUSE9", cpu: "i586") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
