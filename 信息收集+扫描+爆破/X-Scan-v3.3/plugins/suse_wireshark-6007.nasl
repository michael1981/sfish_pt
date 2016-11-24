
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(35729);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  wireshark: fixed capture file crashes (CVE-2009-0599, CVE-2009-0600) and a format string vulnerability (CVE-2009-0601) (wireshark-6007)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch wireshark-6007");
 script_set_attribute(attribute: "description", value: "wireshark: fixed crashes while reading capture files
containing NetScreen data (CVE-2009-0599), Tektronix K12
capture files (CVE-2009-0600) and and a format string
vulnerability (CVE-2009-0601).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch wireshark-6007");
script_end_attributes();

script_cve_id("CVE-2009-0599", "CVE-2009-0600", "CVE-2009-0601");
script_summary(english: "Check for the wireshark-6007 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"wireshark-0.99.6-31.15", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"wireshark-devel-0.99.6-31.15", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
