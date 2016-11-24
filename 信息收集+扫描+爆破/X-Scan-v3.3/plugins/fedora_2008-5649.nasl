
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-5649
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33260);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-5649: ruby");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-5649 (ruby)");
 script_set_attribute(attribute: "description", value: "Ruby is the interpreted scripting language for quick and easy
object-oriented programming.  It has many features to process text
files and to do system management tasks (as in Perl).  It is simple,
straight-forward, and extensible.

-
ChangeLog:


Update information :

* Tue Jun 24 2008 Akira TAGOH <tagoh redhat com> - 1.8.6.230-1
- New upstream release.
- Security fixes. (#452293)
- CVE-2008-1891: WEBrick CGI source disclosure.
- CVE-2008-2662: Integer overflow in rb_str_buf_append().
- CVE-2008-2663: Integer overflow in rb_ary_store().
- CVE-2008-2664: Unsafe use of alloca in rb_str_format().
- CVE-2008-2725: Integer overflow in rb_ary_splice().
- CVE-2008-2726: Integer overflow in rb_ary_splice().
- ruby-1.8.6.111-CVE-2007-5162.patch: removed.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5162", "CVE-2008-1145", "CVE-2008-1891", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");
script_summary(english: "Check for the version of the ruby package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ruby-1.8.6.230-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
