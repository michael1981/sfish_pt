#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19664);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-2491");
 
 name["english"] = "Fedora Core 4 2005-803: pcre";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-803 (pcre).

Perl-compatible regular expression library. PCRE has its own native
API, but a set of 'wrapper' functions that are based on the POSIX API
are also supplied in the library libpcreposix. Note that this just
provides a POSIX calling interface to PCRE; the regular expressions
themselves still follow Perl syntax and semantics. The header file for
the POSIX-style functions is called pcreposix.h.

Update Information:

the new package includes a fix for a heap buffer overflow." );
 script_set_attribute(attribute:"solution", value:
"Get the newest Fedora Updates" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the pcre package";
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
if ( rpm_check( reference:"pcre-5.0-4.1.fc4", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pcre-devel-5.0-4.1.fc4", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"pcre-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2491", value:TRUE);
}
