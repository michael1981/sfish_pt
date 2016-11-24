
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6706
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33841);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 8 2008-6706: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6706 (thunderbird)");
 script_set_attribute(attribute: "description", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

-
Update Information:

Updated thunderbird packages that fix several security issues are now available
for Fedora 8.    Several flaws were found in the processing of malformed HTML
content. An HTML mail containing malicious content could cause Thunderbird to
crash or, potentially, execute arbitrary code as the user running Thunderbird.
(CVE-2008-2785, CVE-2008-2798, CVE-2008-2799, CVE-2008-2811)    Multiple flaws
were found in the processing of malformed JavaScript content. An HTML mail
containing such malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code as the user running Thunderbird.
(CVE-2008-2802, CVE-2008-2803)    A flaw was found in the way a malformed
.properties file was processed by Thunderbird. A malicious extension could read
uninitialized memory, possibly leaking sensitive data to the extension.
(CVE-2008-2807)    A flaw was found in the way Thunderbird displayed informatio
n
about self-signed certificates. It was possible for a self-signed certificate t
o
contain multiple alternate name entries, which were not all displayed to the
user, allowing them to mistakenly extend trust to an unknown site.
(CVE-2008-2809)    Thunderbird was updated to upstream version 2.0.0.16 to
address these flaws:  [9]http://www.mozilla.org/security/known-
vulnerabilities/thunderbird20.html#thunderbird2.0.0.16
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2785", "CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2807", "CVE-2008-2809", "CVE-2008-2811");
script_summary(english: "Check for the version of the thunderbird package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"thunderbird-2.0.0.16-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
