# This script was automatically generated from the dsa-1219
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23742);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1219");
 script_cve_id("CVE-2005-3011", "CVE-2006-4810");
 script_bugtraq_id(14854, 20959);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1219 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple vulnerabilities have been found in the GNU texinfo package, a
documentation system for on-line information and printed output.
CVE-2005-3011
    Handling of temporary files is performed in an insecure manner, allowing
    an attacker to overwrite any file writable by the victim.
CVE-2006-4810
    A buffer overflow in util/texindex.c could allow an attacker to execute
    arbitrary code with the victim\'s access rights by inducing the victim to
    run texindex or tex2dvi on a specially crafted texinfo file.
For the stable distribution (sarge), these problems have been fixed in
version 4.7-2.2sarge2. Note that binary packages for the mipsel
architecture are not currently available due to technical problems with
the build host. These packages will be made available as soon as
possible.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1219');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your texinfo package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1219] DSA-1219-1 texinfo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1219-1 texinfo");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'info', release: '3.1', reference: '4.7-2.2sarge2');
deb_check(prefix: 'texinfo', release: '3.1', reference: '4.7-2.2sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
