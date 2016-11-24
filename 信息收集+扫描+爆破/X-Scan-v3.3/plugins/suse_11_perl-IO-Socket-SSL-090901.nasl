
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41449);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  perl-IO-Socket-SSL (2009-09-01)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for perl-IO-Socket-SSL");
 script_set_attribute(attribute: "description", value: "This update of perl-IO-Socket-SSL improves the hostname
checking of the SSL certificate. (CVE-2009-3024)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for perl-IO-Socket-SSL");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=535554");
script_end_attributes();

 script_cve_id("CVE-2009-3024");
script_summary(english: "Check for the perl-IO-Socket-SSL package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"perl-IO-Socket-SSL-1.16-3.2.1", release:"SLES11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"perl-IO-Socket-SSL-1.16-3.2.1", release:"SLED11", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
