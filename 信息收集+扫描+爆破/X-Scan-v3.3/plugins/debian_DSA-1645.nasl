# This script was automatically generated from the dsa-1645
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34353);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1645");
 script_cve_id("CVE-2008-4298", "CVE-2008-4359", "CVE-2008-4360");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1645 security update');
 script_set_attribute(attribute: 'description', value:
'Several local/remote vulnerabilities have been discovered in lighttpd,
a fast webserver with minimal memory footprint. 
The Common Vulnerabilities and Exposures project identifies the following 
problems:
CVE-2008-4298
    A memory leak in the http_request_parse function could be used by
    remote attackers to cause lighttpd to consume memory, and cause a
    denial of service attack.
CVE-2008-4359
    Inconsistant handling of URL patterns could lead to the disclosure
    of resources a server administrator did not anticipate when using
    rewritten URLs.
CVE-2008-4360
    Upon filesystems which don\'t handle case-insensitive paths differently
    it might be possible that unanticipated resources could be made available
    by mod_userdir.
For the stable distribution (etch), these problems have been fixed in version
1.4.13-4etch11.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1645');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lighttpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1645] DSA-1645-1 lighttpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1645-1 lighttpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lighttpd', release: '4.0', reference: '1.4.13-4etch11');
deb_check(prefix: 'lighttpd-doc', release: '4.0', reference: '1.4.13-4etch11');
deb_check(prefix: 'lighttpd-mod-cml', release: '4.0', reference: '1.4.13-4etch11');
deb_check(prefix: 'lighttpd-mod-magnet', release: '4.0', reference: '1.4.13-4etch11');
deb_check(prefix: 'lighttpd-mod-mysql-vhost', release: '4.0', reference: '1.4.13-4etch11');
deb_check(prefix: 'lighttpd-mod-trigger-b4-dl', release: '4.0', reference: '1.4.13-4etch11');
deb_check(prefix: 'lighttpd-mod-webdav', release: '4.0', reference: '1.4.13-4etch11');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
