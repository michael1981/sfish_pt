
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33574);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  Opera 9.51 security and bugfix update (opera-5468)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch opera-5468");
 script_set_attribute(attribute: "description", value: "Opera 9.51 was released as security and bugfix update.

Full details are on
http://www.opera.com/docs/changelogs/linux/951/

CVE-2008-3078: Opera before 9.51 does not properly manage
memory within functions supporting the CANVAS element,
which allows remote attackers to read uninitialized memory
contents by using JavaScript to read a canvas image.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch opera-5468");
script_end_attributes();

script_cve_id("CVE-2008-3078");
script_summary(english: "Check for the opera-5468 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"opera-9.51-7.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
