
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9386
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(41609);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-9386: proftpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9386 (proftpd)");
 script_set_attribute(attribute: "description", value: "ProFTPD is an enhanced FTP server with a focus toward simplicity, security,
and ease of configuration. It features a very Apache-like configuration
syntax, and a highly customizable server infrastructure, including support for
multiple 'virtual' FTP servers, anonymous FTP, and permission-based directory
visibility.

This package defaults to the standalone behaviour of ProFTPD, but all the
needed scripts to have it run by xinetd instead are included.

-
Update Information:

This update has a large number of changes from previous Fedora packages; the
highlights are as follows:    - Update to upstream release 1.3.2a  - Fix SQL
injection vulnerability at login (#485125, CVE-2009-0542)  - Fix SELinux
compatibility (#498375)  - Fix audit logging (#506735)  - Fix default
configuration (#509251)  - Many new loadable modules including mod_ctrls_admin
and mod_wrap2  - National Language Support (RFC 2640)  - Enable/disable common
features in /etc/sysconfig/proftpd
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0542");
script_summary(english: "Check for the version of the proftpd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"proftpd-1.3.2a-5.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
