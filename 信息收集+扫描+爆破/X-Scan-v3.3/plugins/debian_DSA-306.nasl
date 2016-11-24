# This script was automatically generated from the dsa-306
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15143);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "306");
 script_cve_id("CVE-2003-0321", "CVE-2003-0322", "CVE-2003-0328");
 script_bugtraq_id(7096, 7097, 7099, 7100);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-306 security update');
 script_set_attribute(attribute: 'description', value:
'Timo Sirainen discovered several problems in BitchX, a popular client
for Internet Relay Chat (IRC).  A malicious server could craft special
reply strings, triggering the client to write beyond buffer boundaries
or allocate a negative amount of memory.  This could lead to a denial
of service if the client only crashes, but may also lead to executing
of arbitrary code under the user id of the chatting user.
For the stable distribution (woody) these problems have been fixed in
version 1.0-0c19-1.1.
For the old stable distribution (potato) these problems have been
fixed in version 1.0-0c16-2.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-306');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your BitchX package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA306] DSA-306-1 ircii-pana");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-306-1 ircii-pana");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bitchx', release: '2.2', reference: '1.0-0c16-2.1');
deb_check(prefix: 'bitchx-gtk', release: '2.2', reference: '1.0-0c16-2.1');
deb_check(prefix: 'bitchx', release: '3.0', reference: '1.0-0c19-1.1');
deb_check(prefix: 'bitchx-dev', release: '3.0', reference: '1.0-0c19-1.1');
deb_check(prefix: 'bitchx-gtk', release: '3.0', reference: '1.0-0c19-1.1');
deb_check(prefix: 'bitchx-ssl', release: '3.0', reference: '1.0-0c19-1.1');
deb_check(prefix: 'ircii-pana', release: '2.2', reference: '1.0-0c16-2.1');
deb_check(prefix: 'ircii-pana', release: '3.0', reference: '1.0-0c19-1.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
