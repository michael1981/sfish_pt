
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30100);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for xine (xine-devel-4926)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xine-devel-4926");
 script_set_attribute(attribute: "description", value: "Specially crafted rtsp-Streams could cause a buffer
overflow in xine. Attackers could potentially exploit that
to execute arbitrary code (CVE-2008-0225).

Additionally a security update of xorg-x11 revealed a bug
in xine-ui. The xine user interface didn't display properly
due to that.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch xine-devel-4926");
script_end_attributes();

script_cve_id("CVE-2008-0225");
script_summary(english: "Check for the xine-devel-4926 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"xine-devel-1.1.1-24.26", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xine-lib-1.1.1-24.26", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
