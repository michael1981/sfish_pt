
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-11666
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(42846);
 script_version("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-11666: proftpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-11666 (proftpd)");
 script_set_attribute(attribute: "description", value: "ProFTPD is an enhanced FTP server with a focus toward simplicity, security,
and ease of configuration. It features a very Apache-like configuration
syntax, and a highly customizable server infrastructure, including support for
multiple 'virtual' FTP servers, anonymous FTP, and permission-based directory
visibility.

This package defaults to the standalone behaviour of ProFTPD, but all the
needed scripts to have it run by xinetd instead are included.

-
Update Information:

This update fixes CVE-2009-3639, in which proftpd's mod_tls, when the
dNSNameRequired TLS option is enabled, does not properly handle a '\0' characte
r
in a domain name in the Subject Alternative Name field of an X.509 client
certificate. This allows remote attackers to bypass intended client-hostname
restrictions via a crafted certificate issued by a legitimate Certification
Authority.    This update to upstream release 1.3.2b also fixes the following
issues recorded in the proftpd bug tracker at bugs.proftpd.org:    - Regression
causing command-line define options not to work (bug 3221)  - Use correct cache
d
user values with 'SQLNegativeCache on' (bug 3282)  - Slower transfers of
multiple small files (bug 3284)  - Support MaxTransfersPerHost,
MaxTransfersPerUser properly (bug 3287)  - Handle symlinks to directories with
trailing slashes properly (bug 3297)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-3639");
script_summary(english: "Check for the version of the proftpd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"proftpd-1.3.2b-1.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
