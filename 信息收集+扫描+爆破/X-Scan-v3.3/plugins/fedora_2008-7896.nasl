
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7896
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34180);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-7896: httrack");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7896 (httrack)");
 script_set_attribute(attribute: "description", value: "HTTrack is a free and easy-to-use offline browser utility.

It allows the user to download a World Wide Web site from the Internet to a
local directory, building recursively all directories, getting HTML, images,
and other files from the server to your computer. HTTrack arranges the
original site's relative link-structure. HTTrack can also update an existing
mirrored site, and resume interrupted downloads. HTTrack is fully
configurable, and has an integrated help system.

-
Update Information:


Update information :

* Tue Sep 09 2008 Debarshi Ray <rishi fedoraproject org> - 3.42.93-1  - Version
bump to 3.42.93. Closes Red Hat Bugzilla bugs #457523    (CVE-2008-3429)and
#460529.  - Use of generic macros in the publicly exposed API fixed by upstream
.
- Use of xdg-open now added by upstream.  - OpenSSL version updated by upstream
.
- Linkage issues in libhtsjava.so fixed by upstream.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3429");
script_summary(english: "Check for the version of the httrack package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"httrack-3.42.93-1.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
