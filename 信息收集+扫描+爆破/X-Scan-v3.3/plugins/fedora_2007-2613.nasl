
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2613
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27781);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-2613: proftpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2613 (proftpd)");
 script_set_attribute(attribute: "description", value: "ProFTPD is an enhanced FTP server with a focus toward simplicity, security,
and ease of configuration. It features a very Apache-like configuration
syntax, and a highly customizable server infrastructure, including support for
multiple 'virtual' FTP servers, anonymous FTP, and permission-based directory
visibility.

This package defaults to the standalone behaviour of ProFTPD, but all the
needed scripts to have it run by xinetd instead are included.

-
Update Information:

The Auth API in ProFTPD before 20070417, when multiple simultaneous
authentication modules are configured, does not require that the module that ch
ecks authentication is the same as the module that retrieves authentication dat
a, which might allow remote attackers to bypass authentication, as demonstrated
by use of SQLAuthTypes Plaintext in mod_sql, with data retrieved from /etc/pas
swd.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-2165");
script_summary(english: "Check for the version of the proftpd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"proftpd-1.3.1-2.fc7", release:"FC7") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
