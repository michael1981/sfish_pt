# This script was automatically generated from the dsa-1303
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25465);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1303");
 script_cve_id("CVE-2007-1869", "CVE-2007-1870");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1303 security update');
 script_set_attribute(attribute: 'description', value:
'Two problems were discovered with lighttpd, a fast webserver with
minimal memory footprint, which could allow denial of service.
The Common Vulnerabilities and Exposures project identifies the
following problems:
CVE-2007-1869
  Remote attackers could cause denial of service by disconnecting
  partway through making a request.
CVE-2007-1870
  A NULL pointer dereference could cause a crash when serving files
  with a mtime of 0.
For the stable distribution (etch) these problems have been fixed in
version 1.4.13-4etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1303');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lighttpd package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1303] DSA-1303-1 lighttpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1303-1 lighttpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lighttpd', release: '4.0', reference: '1.4.13-4etch1');
deb_check(prefix: 'lighttpd-doc', release: '4.0', reference: '1.4.13-4etch1');
deb_check(prefix: 'lighttpd-mod-cml', release: '4.0', reference: '1.4.13-4etch1');
deb_check(prefix: 'lighttpd-mod-magnet', release: '4.0', reference: '1.4.13-4etch1');
deb_check(prefix: 'lighttpd-mod-mysql-vhost', release: '4.0', reference: '1.4.13-4etch1');
deb_check(prefix: 'lighttpd-mod-trigger-b4-dl', release: '4.0', reference: '1.4.13-4etch1');
deb_check(prefix: 'lighttpd-mod-webdav', release: '4.0', reference: '1.4.13-4etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
