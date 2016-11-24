# This script was automatically generated from the dsa-1362
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25962);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "1362");
 script_cve_id("CVE-2007-3946", "CVE-2007-3947", "CVE-2007-3949", "CVE-2007-3950", "CVE-2007-4727");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1362 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities were discovered in lighttpd, a fast webserver with
minimal memory footprint, which could allow the execution of arbitrary code via
the overflow of CGI variables when mod_fcgi was enabled.  The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2007-3946
    The use of mod_auth could leave to a denial of service attack crashing
    the webserver.
CVE-2007-3947
    The improper handling of repeated HTTP headers could cause a denial
    of service attack crashing the webserver.
CVE-2007-3949
    A bug in mod_access potentially allows remote users to bypass
    access restrictions via trailing slash characters.
CVE-2007-3950
    On 32-bit platforms users may be able to create denial of service
    attacks, crashing the webserver, via mod_webdav, mod_fastcgi, or
    mod_scgi.
For the stable distribution (etch), these problems have been fixed in version
1.4.13-4etch4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1362');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lighttpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1362] DSA-1362-2 lighttpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1362-2 lighttpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lighttpd', release: '4.0', reference: '1.4.13-4etch4');
deb_check(prefix: 'lighttpd-doc', release: '4.0', reference: '1.4.13-4etch4');
deb_check(prefix: 'lighttpd-mod-cml', release: '4.0', reference: '1.4.13-4etch4');
deb_check(prefix: 'lighttpd-mod-magnet', release: '4.0', reference: '1.4.13-4etch4');
deb_check(prefix: 'lighttpd-mod-mysql-vhost', release: '4.0', reference: '1.4.13-4etch4');
deb_check(prefix: 'lighttpd-mod-trigger-b4-dl', release: '4.0', reference: '1.4.13-4etch4');
deb_check(prefix: 'lighttpd-mod-webdav', release: '4.0', reference: '1.4.13-4etch4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
