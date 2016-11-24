
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40094);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  opera (2008-12-17)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for opera");
 script_set_attribute(attribute: "description", value: "Opera 9.63 fixes the following security problems:

- Manipulating text input contents can allow execution of
  arbitrary code

- HTML parsing flaw can cause Opera to execute arbitrary
  code.

- Long hostnames in file: URLs can cause execution of
  arbitrary code.

- Script injection in feed preview can reveal contents of
  unrelated news feeds.

- Built-in XSLT templates can allow cross-site scripting.

- Fixed an issue that could reveal random data.

- SVG images embedded using <img> tags can no longer
  execute Java or plugin content.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for opera");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=459404");
script_end_attributes();

script_summary(english: "Check for the opera package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"opera-9.63-1.1", release:"SUSE11.0", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"opera-9.63-1.1", release:"SUSE11.0", cpu:"x86_64") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
