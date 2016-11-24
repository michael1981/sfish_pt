#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(18580);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-1992");
 
 name["english"] = "Fedora Core 4 2005-475: ruby";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-475 (ruby).

Ruby is the interpreted scripting language for quick and easy
object-oriented programming.  It has many features to process text
files and to do system management tasks (as in Perl).  It is simple,
straight-forward, and extensible.


* Wed Jun 22 2005 Akira TAGOH <tagoh redhat com> - 1.8.2-7.fc4.2

- ruby-1.8.2-xmlrpc-CVE-2005-1992.patch: fixed the arbitrary command execution
on XMLRPC server. (#161096)" );
 script_set_attribute(attribute:"solution", value:
"http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_ruby-1.8.2-7.fc4.2" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the ruby package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ruby-devel-1.8.2-7.fc4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"irb-1.8.2-7.fc4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rdoc-1.8.2-7.fc4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ri-1.8.2-7.fc4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.2-7.fc4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.8.2-7.fc4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.8.2-7.fc4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-mode-1.8.2-7.fc4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.8.2-7.fc4.2", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"ruby-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-1992", value:TRUE);
}
