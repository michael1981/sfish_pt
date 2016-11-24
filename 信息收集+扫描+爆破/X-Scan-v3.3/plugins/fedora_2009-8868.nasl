
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8868
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40688);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 11 2009-8868: perl-Compress-Raw-Bzip2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8868 (perl-Compress-Raw-Bzip2)");
 script_set_attribute(attribute: "description", value: "This module provides a Perl interface to the bzip2 compression library.
It is used by IO::Compress::Bzip2.

-
Update Information:

Off-by-one error in the bzinflate function in Bzip2.xs in the  Compress-Raw-
Bzip2 module before 2.018 for Perl allows  context-dependent attackers to cause
a denial of service (application hang or crash) via a crafted bzip2 compressed
stream that triggers a buffer overflow, a related issue to CVE-2009-1391.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1391", "CVE-2009-1884");
script_summary(english: "Check for the version of the perl-Compress-Raw-Bzip2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"perl-Compress-Raw-Bzip2-2.020-1.fc11", release:"FC11") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
