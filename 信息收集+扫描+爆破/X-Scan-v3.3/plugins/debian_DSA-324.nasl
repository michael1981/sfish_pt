# This script was automatically generated from the dsa-324
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15161);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "324");
 script_cve_id("CVE-2003-0428", "CVE-2003-0429", "CVE-2003-0431", "CVE-2003-0432");
 script_bugtraq_id(7878, 7880, 7881, 7883);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-324 security update');
 script_set_attribute(attribute: 'description', value:
'Several of the packet dissectors in ethereal contain string handling
bugs which could be exploited using a maliciously crafted packet to
cause ethereal to consume excessive amounts of memory, crash, or
execute arbitrary code.
These vulnerabilities were announced in the following Ethereal security
advisory:
"http://www.ethereal.com/appnotes/enpa-sa-00010.html"
Ethereal 0.9.4 in Debian 3.0 (woody) is affected by most of the
problems described in the advisory, including:
The following problems do not affect this version:
as these modules are not present.
For the stable distribution (woody) these problems have been fixed in
version 0.9.4-1woody5.
For the old stable distribution (potato) these problems will be fixed in a
future advisory.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-324');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-324
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA324] DSA-324-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-324-1 ethereal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody5');
deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody5');
deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody5');
deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
