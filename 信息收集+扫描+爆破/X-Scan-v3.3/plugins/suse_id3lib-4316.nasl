
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27269);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  id3lib: This update fixes a bug that allows local attackers to overwrite arbitrary files. (id3lib-4316)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch id3lib-4316");
 script_set_attribute(attribute: "description", value: "This update fixes a bug that allows local attackers to
overwrite arbitrary files. (CVE-2007-4460)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch id3lib-4316");
script_end_attributes();

script_cve_id("CVE-2007-4460");
script_summary(english: "Check for the id3lib-4316 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"id3lib-3.8.3-126", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"id3lib-devel-3.8.3-126", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"id3lib-examples-3.8.3-126", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
