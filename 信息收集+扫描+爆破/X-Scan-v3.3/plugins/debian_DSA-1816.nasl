# This script was automatically generated from the dsa-1816
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39439);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1816");
 script_cve_id("CVE-2009-1195");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1816 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that the Apache web server did not properly handle
the "Options=" parameter to the AllowOverride directive:
In the stable distribution (lenny), local users could (via .htaccess)
enable script execution in Server Side Includes even in configurations
where the AllowOverride directive contained only
Options=IncludesNoEXEC.
In the oldstable distribution (etch), local users could (via
.htaccess) enable script execution in Server Side Includes and CGI
script execution in configurations where the AllowOverride directive
contained any "Options=" value.
The oldstable distribution (etch), this problem has been fixed in
version 2.2.3-4+etch8.
For the stable distribution (lenny), this problem has been fixed in
version 2.2.9-10+lenny3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1816');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your apache2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1816] DSA-1816-1 apache2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1816-1 apache2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'apache2', release: '4.0', reference: '2.2.3-4+etch8');
deb_check(prefix: 'apache2-doc', release: '4.0', reference: '2.2.3-4+etch8');
deb_check(prefix: 'apache2-mpm-event', release: '4.0', reference: '2.2.3-4+etch8');
deb_check(prefix: 'apache2-mpm-itk', release: '4.0', reference: '2.2.3-01-2+etch2');
deb_check(prefix: 'apache2-mpm-perchild', release: '4.0', reference: '2.2.3-4+etch8');
deb_check(prefix: 'apache2-mpm-prefork', release: '4.0', reference: '2.2.3-4+etch8');
deb_check(prefix: 'apache2-mpm-worker', release: '4.0', reference: '2.2.3-4+etch8');
deb_check(prefix: 'apache2-prefork-dev', release: '4.0', reference: '2.2.3-4+etch8');
deb_check(prefix: 'apache2-src', release: '4.0', reference: '2.2.3-4+etch8');
deb_check(prefix: 'apache2-threaded-dev', release: '4.0', reference: '2.2.3-4+etch8');
deb_check(prefix: 'apache2-utils', release: '4.0', reference: '2.2.3-4+etch8');
deb_check(prefix: 'apache2.2-common', release: '4.0', reference: '2.2.3-4+etch8');
deb_check(prefix: 'apache2', release: '5.0', reference: '2.2.9-10+lenny3');
deb_check(prefix: 'apache2-dbg', release: '5.0', reference: '2.2.9-10+lenny3');
deb_check(prefix: 'apache2-doc', release: '5.0', reference: '2.2.9-10+lenny3');
deb_check(prefix: 'apache2-mpm-event', release: '5.0', reference: '2.2.9-10+lenny3');
deb_check(prefix: 'apache2-mpm-itk', release: '5.0', reference: '2.2.6-02-1+lenny1');
deb_check(prefix: 'apache2-mpm-prefork', release: '5.0', reference: '2.2.9-10+lenny3');
deb_check(prefix: 'apache2-mpm-worker', release: '5.0', reference: '2.2.9-10+lenny3');
deb_check(prefix: 'apache2-prefork-dev', release: '5.0', reference: '2.2.9-10+lenny3');
deb_check(prefix: 'apache2-src', release: '5.0', reference: '2.2.9-10+lenny3');
deb_check(prefix: 'apache2-suexec', release: '5.0', reference: '2.2.9-10+lenny3');
deb_check(prefix: 'apache2-suexec-custom', release: '5.0', reference: '2.2.9-10+lenny3');
deb_check(prefix: 'apache2-threaded-dev', release: '5.0', reference: '2.2.9-10+lenny3');
deb_check(prefix: 'apache2-utils', release: '5.0', reference: '2.2.9-10+lenny3');
deb_check(prefix: 'apache2.2-common', release: '5.0', reference: '2.2.9-10+lenny3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
