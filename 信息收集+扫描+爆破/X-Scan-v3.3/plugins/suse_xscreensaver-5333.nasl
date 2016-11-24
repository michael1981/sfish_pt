
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33742);
 script_version ("$Revision: 1.7 $");
 script_name(english: "SuSE Security Update:  xscreensaver: Security update to fix NIS issue (xscreensaver-5333)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xscreensaver-5333");
 script_set_attribute(attribute: "description", value: "Following security problem is fixed by this patch:

CVE-2008-1683: When getpwuid() fails (due to dropped
network on NIS accounts) fail instead of silently disabling
locking (and just blanking).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch xscreensaver-5333");
script_end_attributes();

 script_cve_id("CVE-2008-0887");
script_summary(english: "Check for the xscreensaver-5333 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"xscreensaver-5.01-18", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
