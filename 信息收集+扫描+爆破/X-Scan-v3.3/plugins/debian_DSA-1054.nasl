# This script was automatically generated from the dsa-1054
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22596);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1054");
 script_cve_id("CVE-2006-2024", "CVE-2006-2025", "CVE-2006-2026");
 script_bugtraq_id(17730, 17732, 17733);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1054 security update');
 script_set_attribute(attribute: 'description', value:
'Tavis Ormandy discovered several vulnerabilities in the TIFF library
that can lead to a denial of service or the execution of arbitrary
code.  The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2006-2024
    Multiple vulnerabilities allow attackers to cause a denial of
    service.
CVE-2006-2025
    An integer overflow allows attackers to cause a denial of service
    and possibly execute arbitrary code.
CVE-2006-2026
    A double-free vulnerability allows attackers to cause a denial of
    service and possibly execute arbitrary code.
For the old stable distribution (woody) these problems have been fixed
in version 3.5.5-7woody1.
For the stable distribution (sarge) these problems have been fixed in
version 3.7.2-3sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1054');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libtiff packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1054] DSA-1054-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1054-1 tiff");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libtiff-tools', release: '3.0', reference: '3.5.5-7woody1');
deb_check(prefix: 'libtiff3g', release: '3.0', reference: '3.5.5-7woody1');
deb_check(prefix: 'libtiff3g-dev', release: '3.0', reference: '3.5.5-7woody1');
deb_check(prefix: 'libtiff-opengl', release: '3.1', reference: '3.7.2-3sarge1');
deb_check(prefix: 'libtiff-tools', release: '3.1', reference: '3.7.2-3sarge1');
deb_check(prefix: 'libtiff4', release: '3.1', reference: '3.7.2-3sarge1');
deb_check(prefix: 'libtiff4-dev', release: '3.1', reference: '3.7.2-3sarge1');
deb_check(prefix: 'libtiffxx0', release: '3.1', reference: '3.7.2-3sarge1');
deb_check(prefix: 'tiff', release: '3.1', reference: '3.7.2-3sarge1');
deb_check(prefix: 'tiff', release: '3.0', reference: '3.5.5-7woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
