
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27462);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  tar: Securityupdate to fix symlink traversal (tar-2343)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch tar-2343");
 script_set_attribute(attribute: "description", value: "This security update fixes a directory traversal in tar,
where unpacked symlinks could be followed outside of the
directory where the tar file is unpacked. (CVE-2006-6097)

This feature was made optional and needs to be enabled with
a commandline option.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch tar-2343");
script_end_attributes();

script_cve_id("CVE-2006-6097");
script_summary(english: "Check for the tar-2343 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"tar-1.15.1-23.5", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
