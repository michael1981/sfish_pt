
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27244);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  gpg: Security update to fix crash on special crafted messages (gpg-1664)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch gpg-1664");
 script_set_attribute(attribute: "description", value: "It is possible to crash (denial of service) the GNU Privacy 
Guard (gpg) by supplying a specifically crafted message 
specifying a very large UID, which leads to an out of 
memory situation or an integer overflow.  It is unclear if 
this problem can be exploited to execute code.  This issue 
is tracked by the Mitre CVE ID CVE-2006-3082.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch gpg-1664");
script_end_attributes();

script_cve_id("CVE-2006-3082");
script_summary(english: "Check for the gpg-1664 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"gpg-1.4.2-23.4", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
