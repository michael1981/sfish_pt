
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42397);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  apache2-mod_jk security update (apache2-mod_jk-6599)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch apache2-mod_jk-6599");
 script_set_attribute(attribute: "description", value: "Certain HTTP request could confuse the JK connector in
Apache Tomcat which could result in a user seeing responses
destined for other users (CVE-2008-5519).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch apache2-mod_jk-6599");
script_end_attributes();

script_cve_id("CVE-2008-5519");
script_summary(english: "Check for the apache2-mod_jk-6599 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"apache2-mod_jk-1.2.21-59.4", release:"SUSE10.3") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
