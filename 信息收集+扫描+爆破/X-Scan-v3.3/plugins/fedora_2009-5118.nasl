
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-5118
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38812);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2009-5118: giflib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-5118 (giflib)");
 script_set_attribute(attribute: "description", value: "The giflib package contains a shared library of functions for loading and
saving GIF format image files. It is API and ABI compatible with libungif,
the library which supported uncompressed GIFs while the Unisys LZW patent
was in effect.

-
Update Information:

- CVE-2005-2974: NULL pointer dereference crash (#494826)  - CVE-2005-3350:
Memory corruption via a crafted GIF (#494823)  - Solved multilib problems with
documentation (#465208, #474538)  - Removed static library from giflib-devel
package (#225796 #c1)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2005-2974", "CVE-2005-3350");
script_summary(english: "Check for the version of the giflib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"giflib-4.1.3-10.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
