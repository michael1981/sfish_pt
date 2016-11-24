
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27289);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  kdelibs3 security update (kdelibs3-3058)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch kdelibs3-3058");
 script_set_attribute(attribute: "description", value: "A bug in KHTML could be exploited to conduct cross site
scripting (XSS) attacks (CVE-2007-0537).

Another bug allowed attackers to abuse the FTP passive mode
for portscans (CVE-2007-1564).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch kdelibs3-3058");
script_end_attributes();

script_cve_id("CVE-2007-0537", "CVE-2007-1564");
script_summary(english: "Check for the kdelibs3-3058 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"kdelibs3-3.5.5-45.4", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdelibs3-32bit-3.5.5-45.4", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdelibs3-64bit-3.5.5-45.4", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.5.5-45.4", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
