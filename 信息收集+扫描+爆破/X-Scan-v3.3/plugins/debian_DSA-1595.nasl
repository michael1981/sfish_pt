# This script was automatically generated from the dsa-1595
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33176);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1595");
 script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1595 security update');
 script_set_attribute(attribute: 'description', value:
'Several local vulnerabilities have been discovered in the X Window system.
The Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2008-1377
    Lack of validation of the parameters of the
    SProcSecurityGenerateAuthorization and SProcRecordCreateContext
    functions makes it possible for a specially crafted request to trigger
    the swapping of bytes outside the parameter of these requests, causing
    memory corruption.
CVE-2008-1379
    An integer overflow in the validation of the parameters of the
    ShmPutImage() request makes it possible to trigger the copy of
    arbitrary server memory to a pixmap that can subsequently be read by
    the client, to read arbitrary parts of the X server memory space.
CVE-2008-2360
    An integer overflow may occur in the computation of the size of the
    glyph to be allocated by the AllocateGlyph() function which will cause
    less memory to be allocated than expected, leading to later heap
    overflow.
CVE-2008-2361
    An integer overflow may occur in the computation of the  size of the
    glyph to be allocated by the ProcRenderCreateCursor() function which
    will cause less memory to be allocated than expected, leading later
    to dereferencing un-mapped memory, causing a crash of the X server.
CVE-2008-2362
    Integer overflows can also occur in the code validating the parameters
    for the SProcRenderCreateLinearGradient, SProcRenderCreateRadialGradient
    and SProcRenderCreateConicalGradient functions, leading to memory
    corruption by swapping bytes outside of the intended request
    parameters.
For the stable distribution (etch), these problems have been fixed in version
2:1.1.1-21etch5.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1595');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xorg-server package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1595] DSA-1595-1 xorg-server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1595-1 xorg-server");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'xdmx', release: '4.0', reference: '1.1.1-21etch5');
deb_check(prefix: 'xdmx-tools', release: '4.0', reference: '1.1.1-21etch5');
deb_check(prefix: 'xnest', release: '4.0', reference: '1.1.1-21etch5');
deb_check(prefix: 'xserver-xephyr', release: '4.0', reference: '1.1.1-21etch5');
deb_check(prefix: 'xserver-xorg-core', release: '4.0', reference: '1.1.1-21etch5');
deb_check(prefix: 'xserver-xorg-dev', release: '4.0', reference: '1.1.1-21etch5');
deb_check(prefix: 'xvfb', release: '4.0', reference: '1.1.1-21etch5');
deb_check(prefix: 'xorg-server', release: '4.0', reference: '1.1.1-21etch5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
