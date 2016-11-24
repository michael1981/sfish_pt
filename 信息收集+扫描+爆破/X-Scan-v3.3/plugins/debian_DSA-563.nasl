# This script was automatically generated from the dsa-563
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15661);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "563");
 script_cve_id("CVE-2004-0884");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-563 security update');
 script_set_attribute(attribute: 'description', value:
'This advisory is an addition to DSA 563-1 and 563-2 which weren\'t able
to supersede the library on sparc and arm due to a different version
number for them in the stable archive. Other architectures were
updated properly. Another problem was reported in connection with
sendmail, though, which should be fixed with this update as well.
For the stable distribution (woody) this problem has been fixed in
version 1.5.27-3.1woody5.
For reference the advisory text follows:
A vulnerability has been discovered in the Cyrus implementation of the
SASL library, the Simple Authentication and Security Layer, a method
for adding authentication support to connection-based protocols.  The
library honors the environment variable SASL_PATH blindly, which
allows a local user to link against a malicious library to run
arbitrary code with the privileges of a setuid or setgid application.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-563');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libsasl packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA563] DSA-563-3 cyrus-sasl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-563-3 cyrus-sasl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libsasl-dev', release: '3.0', reference: '1.5.27-3.1woody5');
deb_check(prefix: 'libsasl-digestmd5-plain', release: '3.0', reference: '1.5.27-3.1woody5');
deb_check(prefix: 'libsasl-modules-plain', release: '3.0', reference: '1.5.27-3.1woody5');
deb_check(prefix: 'libsasl7', release: '3.0', reference: '1.5.27-3.1woody5');
deb_check(prefix: 'sasl-bin', release: '3.0', reference: '1.5.27-3.1woody5');
deb_check(prefix: 'cyrus-sasl', release: '3.0', reference: '1.5.27-3.1woody5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
