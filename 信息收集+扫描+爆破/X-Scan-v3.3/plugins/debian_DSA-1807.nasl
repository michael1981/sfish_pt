# This script was automatically generated from the dsa-1807
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39332);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1807");
 script_cve_id("CVE-2009-0688");
 script_xref(name: "CERT", value: "238019");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1807 security update');
 script_set_attribute(attribute: 'description', value:
'James Ralston discovered that the sasl_encode64() function of cyrus-sasl2,
a free library implementing the Simple Authentication and Security Layer,
suffers from a missing null termination in certain situations.  This causes
several buffer overflows in situations where cyrus-sasl2 itself requires
the string to be null terminated which can lead to denial of service or
arbitrary code execution.
Important notice (Quoting from US-CERT):
While this patch will fix currently vulnerable code, it can cause
non-vulnerable existing code to break. Here\'s a function prototype from
include/saslutil.h to clarify my explanation:
/* base64 encode
* in -- input data
* inlen -- input data length
* out -- output buffer (will be NUL terminated)
* outmax -- max size of output buffer
* result:
* outlen -- gets actual length of output buffer (optional)
*
* Returns SASL_OK on success, SASL_BUFOVER if result won\'t fit
*/
LIBSASL_API int sasl_encode64(const char *in, unsigned inlen,
char *out, unsigned outmax,
unsigned *outlen);

Assume a scenario where calling code has been written in such a way that it
calculates the exact size required for base64 encoding in advance, then
allocates a buffer of that exact size, passing a pointer to the buffer into
sasl_encode64() as *out. As long as this code does not anticipate that the
buffer is NUL-terminated (does not call any string-handling functions like
strlen(), for example) the code will work and it will not be vulnerable.
Once this patch is applied, that same code will break because sasl_encode64()
will begin to return SASL_BUFOVER.
For the oldstable distribution (etch), this problem has been fixed
in version 2.1.22.dfsg1-8+etch1 of cyrus-sasl2.
For the stable distribution (lenny), this problem has been fixed in
version 2.1.22.dfsg1-23+lenny1 of cyrus-sasl2 and cyrus-sasl2-heimdal.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1807');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cyrus-sasl2/cyrus-sasl2-heimdal packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1807] DSA-1807-1 cyrus-sasl2, cyrus-sasl2-heimdal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1807-1 cyrus-sasl2, cyrus-sasl2-heimdal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cyrus-sasl2-dbg', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
deb_check(prefix: 'cyrus-sasl2-doc', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
deb_check(prefix: 'cyrus-sasl2-heimdal-dbg', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
deb_check(prefix: 'libsasl2-2', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
deb_check(prefix: 'libsasl2-dev', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
deb_check(prefix: 'libsasl2-modules', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
deb_check(prefix: 'libsasl2-modules-gssapi-heimdal', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
deb_check(prefix: 'libsasl2-modules-gssapi-mit', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
deb_check(prefix: 'libsasl2-modules-ldap', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
deb_check(prefix: 'libsasl2-modules-otp', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
deb_check(prefix: 'libsasl2-modules-sql', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
deb_check(prefix: 'sasl2-bin', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
deb_check(prefix: 'cyrus-sasl2', release: '4.0', reference: '2.1.22.dfsg1-8+etch1');
deb_check(prefix: 'cyrus-sasl2', release: '5.0', reference: '2.1.22.dfsg1-23+lenny1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
