
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33091);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  vorbis-tools security update (vorbis-tools-5192)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch vorbis-tools-5192");
 script_set_attribute(attribute: "description", value: "Specially crafted files or streams could potentially be
abused to trick applications that support speex into
executing arbitrary code (CVE-2008-1686).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch vorbis-tools-5192");
script_end_attributes();

script_cve_id("CVE-2008-1686");
script_summary(english: "Check for the vorbis-tools-5192 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"vorbis-tools-1.1.1-112.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
