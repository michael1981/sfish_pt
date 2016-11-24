# This script was automatically generated from the dsa-412
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15249);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "412");
 script_cve_id("CVE-2004-0014");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-412 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple vulnerabilities were discovered in nd, a command-line WebDAV
interface, whereby long strings received from the remote server could
overflow fixed-length buffers.  This vulnerability could be exploited
by a remote attacker in control of a malicious WebDAV server to
execute arbitrary code if the server was accessed by a vulnerable
version of nd.
For the current stable distribution (woody) this problem has been
fixed in version 0.5.0-1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-412');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-412
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA412] DSA-412-1 nd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-412-1 nd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'nd', release: '3.0', reference: '0.5.0-1woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
