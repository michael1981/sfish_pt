
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41597);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for Websphere Community Edition (websphere-as_ce-6312)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch websphere-as_ce-6312");
 script_set_attribute(attribute: "description", value: "This update of WebSphere fixes the following
vulnerabilities:
- GERONIMO-3838: close potential denial of service attack
- CVE-2008-5518: fix Apache Geronimo web administration
  console directory traversal vulnerabilities.
- CVE-2009-0038:  fix Apache Geronimo web administration
  console XSS vulnerabilities.
- CVE-2009-0039: fix Apache Geronimo web administration
  console XSRF vulnerabilities.
- CVE-2009-0781: Samples: Fix Apache Tomcat cross-site
  scripting vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch websphere-as_ce-6312");
script_end_attributes();

script_cve_id("CVE-2008-5518", "CVE-2009-0038", "CVE-2009-0039", "CVE-2009-0781");
script_summary(english: "Check for the websphere-as_ce-6312 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"websphere-as_ce-2.1.1.2-0.3", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
