# This script was automatically generated from the dsa-1738
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35908);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1738");
 script_cve_id("CVE-2009-0037");
 script_bugtraq_id(33962);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1738 security update');
 script_set_attribute(attribute: 'description', value:
'David Kierznowski discovered that libcurl, a multi-protocol file transfer
library, when configured to follow URL redirects automatically, does not
question the new target location.  As libcurl also supports file:// and
scp:// URLs - depending on the setup - an untrusted server could use that
to expose local files, overwrite local files or even execute arbitrary
code via a malicious URL redirect.
This update introduces a new option called CURLOPT_REDIR_PROTOCOLS which by
default does not include the scp and file protocol handlers.
For the oldstable distribution (etch) this problem has been fixed in
version 7.15.5-1etch2.
For the stable distribution (lenny) this problem has been fixed in
version 7.18.2-8lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1738');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your curl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1738] DSA-1738-1 curl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1738-1 curl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'curl', release: '4.0', reference: '7.15.5-1etch2');
deb_check(prefix: 'libcurl3', release: '4.0', reference: '7.15.5-1etch2');
deb_check(prefix: 'libcurl3-dbg', release: '4.0', reference: '7.15.5-1etch2');
deb_check(prefix: 'libcurl3-dev', release: '4.0', reference: '7.15.5-1etch2');
deb_check(prefix: 'libcurl3-gnutls', release: '4.0', reference: '7.15.5-1etch2');
deb_check(prefix: 'libcurl3-gnutls-dev', release: '4.0', reference: '7.15.5-1etch2');
deb_check(prefix: 'libcurl3-openssl-dev', release: '4.0', reference: '7.15.5-1etch2');
deb_check(prefix: 'curl', release: '5.0', reference: '7.18.2-8lenny2');
deb_check(prefix: 'libcurl3', release: '5.0', reference: '7.18.2-8lenny2');
deb_check(prefix: 'libcurl3-dbg', release: '5.0', reference: '7.18.2-8lenny2');
deb_check(prefix: 'libcurl3-gnutls', release: '5.0', reference: '7.18.2-8lenny2');
deb_check(prefix: 'libcurl4-gnutls-dev', release: '5.0', reference: '7.18.2-8lenny2');
deb_check(prefix: 'libcurl4-openssl-dev', release: '5.0', reference: '7.18.2-8lenny2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
