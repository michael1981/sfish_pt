#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(19294);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-1849");
 
 name["english"] = "Fedora Core 4 2005-626: zlib";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the patch for the advisory FEDORA-2005-626 (zlib).

Zlib is a general-purpose, patent-free, lossless data compression
library which is used by many different programs.


* Fri Jul 22 2005 Ivana Varekova <varekova@redhat.com> 1.2.2.2-5.fc4
- fix bug 163038 - CVE-2005-1849 - zlib buffer overflow" );
 script_set_attribute(attribute:"solution", value:
"http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_zlib-1.2.2.2-5.fc4" );
 script_set_attribute(attribute:"risk_factor", value:"High" );



 script_end_attributes();

 
 summary["english"] = "Check for the version of the zlib package";
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
if ( rpm_check( reference:"zlib-1.2.2.2-5.fc4", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.2.2.2-5.fc4", release:"FC4") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_exists(rpm:"zlib-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-1849", value:TRUE);
}
