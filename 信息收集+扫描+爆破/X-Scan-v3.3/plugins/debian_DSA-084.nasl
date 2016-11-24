# This script was automatically generated from the dsa-084
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2008 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2008 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include("compat.inc");

if (description) {
 script_id(14921);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "084");
 script_cve_id("CVE-1999-1562");
 script_bugtraq_id(3446);

 script_set_attribute(attribute: "synopsis", value: "The remote host is missing the DSA-084 security update.");
 script_set_attribute(attribute: "description", value: 
'Stephane Gaudreault told us that version 2.0.6a of gftp displays the
password in plain text on the screen within the log window when it is
logging into an ftp server.  A malicious colleague who is watching the
screen could gain access to the users shell on the remote machine.

This problem has been fixed by the Security Team in version 2.0.6a-3.2
for the stable Debian GNU/Linux 2.2.');
 script_set_attribute(attribute: "see_also", value: "http://www.debian.org/security/2001/dsa-084");
 script_set_attribute(attribute:"solution", value:
"Read http://www.debian.org/security/2001/dsa-084
and install the recommended updated packages." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_end_attributes();

 script_copyright(english: "This script is (C) 2008-2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA084] DSA-084-1 gftp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-084-1 gftp");
 exit(0);
}

include("debian_package.inc");

deb_check(prefix: 'gftp', release: '2.2', reference: '2.0.6a-3.2');
if (deb_report_get()) security_warning(port: 0, extra: deb_report_get());
