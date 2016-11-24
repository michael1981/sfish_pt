# This script was automatically generated from the dsa-083
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2008 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2008 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include("compat.inc");

if (description) {
 script_id(14920);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "083");
 script_cve_id("CVE-2001-0905");

 script_set_attribute(attribute: "synopsis", value: "The remote host is missing the DSA-083 security update.");

 script_set_attribute(attribute: "description", value: 
'Using older versions of procmail it was possible to make procmail
crash by sending it signals.  On systems where procmail is installed
setuid this could be exploited to obtain unauthorized privileges.

This problem has been fixed in version 3.20 by the upstream
maintainer, included in Debian unstable, and was ported back to
version 3.15.2 which is available for the stable Debian GNU/Linux
2.2.');
 script_set_attribute(attribute:"solution", value:
"Read http://www.debian.org/security/2001/dsa-083
and install the recommended updated packages." );
 script_set_attribute(attribute: "see_also", value: "http://www.debian.org/security/2001/dsa-083");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
 script_end_attributes();
 script_copyright(english: "This script is (C) 2008-2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA083] DSA-083-1 procmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-083-1 procmail");
 exit(0);
}

include("debian_package.inc");

deb_check(prefix: 'procmail', release: '2.2', reference: '3.15.2-1');
if (deb_report_get()) security_warning(port: 0, extra: deb_report_get());
