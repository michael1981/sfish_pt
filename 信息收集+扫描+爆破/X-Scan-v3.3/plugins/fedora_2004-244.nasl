#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(13851);
 script_bugtraq_id(10819);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0557");
 
 name["english"] = "Fedora Core 2 2004-244: sox";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2004-244 (sox).

SoX (Sound eXchange) is a sound file format converter SoX can convert
between many different digitized sound formats and perform simple
sound manipulation functions, including sound effects.

Update Information:

Updated sox packages that fix buffer overflows in the WAV file handling
code are now available.
     
Buffer overflows existed in the parsing of WAV file header fields. It
was possible that a malicious WAV file could have caused arbitrary
code to be executed when the file was played or converted." );
 script_set_attribute(attribute:"solution", value:
"http://www.fedoranews.org/updates/FEDORA-2004-244.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the sox package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"sox-12.17.4-4.fc2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sox-devel-12.17.4-4.fc2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sox-debuginfo-12.17.4-4.fc2", release:"FC2") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"sox-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0557", value:TRUE);
}
