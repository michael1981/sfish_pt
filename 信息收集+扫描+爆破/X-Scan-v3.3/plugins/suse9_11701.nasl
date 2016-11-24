
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41145);
 script_version("$Revision: 1.2 $");
 script_name(english: "SuSE9 Security Update:  Security update for netpbm (11701)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 11701");
 script_set_attribute(attribute: "description", value: 'This update fixes a buffer overflow in the RGBA-palette code.
The bug can be abused to trigger a denial-or-service attack
by feeding untrusted data to "pnmtopng -alpha" (maybe via a
remote service like a CGI, mail user agent, etc.) The
execution of arbitrary code is theoretically possible but
unlikely. Another possible buffer overflow that can occur
while handling a textline has been fixed as well.
(CVE-2005-3632)
This is a reissue of an earlier patch to fix version problems
with the previous release.
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch 11701");
script_end_attributes();

script_cve_id("CVE-2005-3632");
script_summary(english: "Check for the security advisory #11701");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libnetpbm-1.0.0-618.14", release:"SUSE9", cpu: "i586") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"netpbm-10.11.4-172.14", release:"SUSE9", cpu: "i586") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
