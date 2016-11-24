
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41596);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  Security update for Websphere Community Edition (websphere-as_ce-5850)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch websphere-as_ce-5850");
 script_set_attribute(attribute: "description", value: "Websphere has been updated to version 2.1.0.1 to fix
several security vulnerability in the included subprojects,
such as Apache Geronimo and Tomcat (CVE-2007-0184,
CVE-2007-0185, CVE-2007-2377, CVE-2007-2449, CVE-2007-2450,
CVE-2007-3382, CVE-2007-3385, CVE-2007-3386, CVE-2007-5333,
CVE-2007-5342, CVE-2007-5461, CVE-2007-5613, CVE-2007-5615,
CVE-2007-6286, CVE-2008-0002, CVE-2008-1232, CVE-2008-1947,
CVE-2008-2370, CVE-2008-2938).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch websphere-as_ce-5850");
script_end_attributes();

script_cve_id("CVE-2007-0184", "CVE-2007-0185", "CVE-2007-2377", "CVE-2007-2449", "CVE-2007-2450", "CVE-2007-3382", "CVE-2007-3385", "CVE-2007-3386", "CVE-2007-5333", "CVE-2007-5342", "CVE-2007-5461", "CVE-2007-5613", "CVE-2007-5615", "CVE-2007-6286", "CVE-2008-0002", "CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2370", "CVE-2008-2938");
script_summary(english: "Check for the websphere-as_ce-5850 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"websphere-as_ce-2.1.0.1-3.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
