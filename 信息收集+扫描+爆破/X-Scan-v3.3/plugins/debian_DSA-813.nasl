# This script was automatically generated from the dsa-813
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19709);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "813");
 script_cve_id("CVE-2005-2369", "CVE-2005-2370", "CVE-2005-2448");
 script_bugtraq_id(14415);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-813 security update');
 script_set_attribute(attribute: 'description', value:
'Several problems have been discovered in libgadu which is also part of
centericq, a text-mode multi-protocol instant messenger client.  The
Common Vulnerabilities and Exposures project identifies the following
problems:
    Multiple integer signedness errors may allow remote attackers to
    cause a denial of service or execute arbitrary code.
    Memory alignment errors may allows remote attackers to cause a
    denial of service on certain architectures such as sparc.
    Several endianess errors may allow remote attackers to cause a
    denial of service.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 4.20.0-1sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-813');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your centericq package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA813] DSA-813-1 centericq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-813-1 centericq");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'centericq', release: '3.1', reference: '4.20.0-1sarge2');
deb_check(prefix: 'centericq-common', release: '3.1', reference: '4.20.0-1sarge2');
deb_check(prefix: 'centericq-fribidi', release: '3.1', reference: '4.20.0-1sarge2');
deb_check(prefix: 'centericq-utf8', release: '3.1', reference: '4.20.0-1sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
