# This script was automatically generated from the dsa-434
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15271);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "434");
 script_cve_id("CVE-2004-0005", "CVE-2004-0006", "CVE-2004-0007", "CVE-2004-0008");
 script_bugtraq_id(9489);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-434 security update');
 script_set_attribute(attribute: 'description', value:
'Stefan Esser discovered several security related problems in Gaim, a
multi-protocol instant messaging client.  Not all of them are
applicable for the version in Debian stable, but affected the version
in the unstable distribution at least.  The problems were grouped for
the Common Vulnerabilities and Exposures as follows:
    When the Yahoo Messenger handler decodes an octal value for email
    notification functions two different kinds of overflows can be
    triggered.  When the MIME decoder decoded a quoted printable
    encoded string for email notification two other different kinds of
    overflows can be triggered.  These problems only affect the
    version in the unstable distribution.
    When parsing the cookies within the HTTP reply header of a Yahoo
    web connection a buffer overflow can happen.  When parsing the
    Yahoo Login Webpage the YMSG protocol overflows stack buffers if
    the web page returns oversized values.  When splitting a URL into
    its parts a stack overflow can be caused.  These problems only
    affect the version in the unstable distribution.
    When an oversized keyname is read from a Yahoo Messenger packet a
    stack overflow can be triggered.  When Gaim is setup to use an HTTP
    proxy for connecting to the server a malicious HTTP proxy can
    exploit it.  These problems affect all versions Debian ships.
    However, the connection to Yahoo doesn\'t work in the version in
    Debian stable.
    Internally data is copied between two tokens into a fixed size
    stack buffer without a size check.  This only affects the version
    of gaim in the unstable distribution.
    When allocating memory for AIM/Oscar DirectIM packets an integer
    overflow can happen, resulting in a heap overflow.  This only
    affects the version of gaim in the unstable distribution.
For the stable distribution (woody) these problems has been fixed in
version 0.58-2.4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-434');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gaim packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA434] DSA-434-1 gaim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-434-1 gaim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gaim', release: '3.0', reference: '0.58-2.4');
deb_check(prefix: 'gaim-common', release: '3.0', reference: '0.58-2.4');
deb_check(prefix: 'gaim-gnome', release: '3.0', reference: '0.58-2.4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
