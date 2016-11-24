
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36892);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDKA-2007:062: rpmdrake");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKA-2007:062 (rpmdrake).");
 script_set_attribute(attribute: "description", value: "The rpmdrake package, which provides the graphical software
installation and update tools rpmdrake, drakrpm-edit-media and
MandrivaUpdate), included with Mandriva Linux 2007 Spring contains
several bugs. These include:
When installing software with rpmdrake, if packages are selected for
installation which require other packages to be installed as well,
a message will be displayed that says To satisfy dependencies,
the following packages also need to be installed:, but no list of
dependencies will actually be shown.
When installing software with rpmdrake, searching for a package always
searches through the full set of available packages even when a search
filter - such as All updates or Mandriva choices - is selected.
When installing software with rpmdrake, when you switch between two
subsections with the same name - for instance, System/Settings/Other
and Development/Other - the list of packages is not updated; in
the example, the packages from the System/Settings/Other group
will continue to be displayed, instead of the packages from
Development/Other.
Running rpmdrake with the --merge-all-rpmnew parameter, which uses
rpmdrake to help you merge changes in updated configuration files,
does not work.
When updating your system with MandrivaUpdate, when a package name
cannot be correctly parsed, the name of the previous package in the
list will be displayed again instead.
When installing software with rpmdrake, the application will crash
if a package with a malformed summary in the Unicode text encoding
system was selected.
Some other, more minor bugs were also fixed in this update.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKA-2007:062");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the rpmdrake package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"park-rpmdrake-3.68-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rpmdrake-3.68-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
