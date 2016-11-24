# This script was automatically generated from the dsa-455
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15292);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "455");
 script_cve_id("CVE-2004-0110");
 script_bugtraq_id(9718);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-455 security update');
 script_set_attribute(attribute: 'description', value:
'libxml2 is a library for manipulating XML files.
Yuuichi Teranishi (&#23546;&#35199; &#35029;&#19968;)
discovered a flaw in libxml, the GNOME XML library.
When fetching a remote resource via FTP or HTTP, the library uses
special parsing routines which can overflow a buffer if passed a very
long URL.  If an attacker is able to find an application using libxml1
or libxml2 that parses remote resources and allows the attacker to
craft the URL, then this flaw could be used to execute arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 1.8.17-2woody1 of libxml and version 2.4.19-4woody1 of libxml2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-455');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libxml1 and libxml2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA455] DSA-455-1 libxml");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-455-1 libxml");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libxml-dev', release: '3.0', reference: '1.8.17-2woody1');
deb_check(prefix: 'libxml1', release: '3.0', reference: '1.8.17-2woody1');
deb_check(prefix: 'libxml2', release: '3.0', reference: '2.4.19-4woody1');
deb_check(prefix: 'libxml2-dev', release: '3.0', reference: '2.4.19-4woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
