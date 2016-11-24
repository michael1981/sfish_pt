
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34942);
 script_version ("$Revision: 1.7 $");
 script_name(english: "SuSE Security Update:  Security update for Acrobat Reader (acroread-5746)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch acroread-5746");
 script_set_attribute(attribute: "description", value: "The acroread package was update to fix several security
vulnerabilities in the JavaScript engine. (CVE-2008-2992,
CVE-2008-2549, CVE-2008-4812, CVE-2008-4813, CVE-2008-4817,
CVE-2008-4816, CVE-2008-4814, CVE-2008-4815)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch acroread-5746");
script_end_attributes();

script_cve_id("CVE-2008-2549", "CVE-2008-2992", "CVE-2008-4812", "CVE-2008-4813", "CVE-2008-4814", "CVE-2008-4815", "CVE-2008-4816", "CVE-2008-4817");
script_summary(english: "Check for the acroread-5746 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"acroread-8.1.3-1.1", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
