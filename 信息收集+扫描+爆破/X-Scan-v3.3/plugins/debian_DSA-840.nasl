# This script was automatically generated from the dsa-840
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19809);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "840");
 script_cve_id("CVE-2005-2498");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-840 security update');
 script_set_attribute(attribute: 'description', value:
'Stefan Esser of the Hardened-PHP Project reported a serious vulnerability
in the third-party XML-RPC library included with some Drupal versions.  An
attacker could execute arbitrary PHP code on a target site.  This update
pulls in the latest XML-RPC version from upstream.
The old stable distribution (woody) is not affected by this problem since
no drupal is included.
For the stable distribution (sarge) this problem has been fixed in
version 4.5.3-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-840');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your drupal package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA840] DSA-840-1 drupal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-840-1 drupal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'drupal', release: '3.1', reference: '4.5.3-4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
