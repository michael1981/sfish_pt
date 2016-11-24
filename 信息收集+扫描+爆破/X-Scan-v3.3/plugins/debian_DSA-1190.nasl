# This script was automatically generated from the dsa-1190
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22904);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "1190");
 script_cve_id("CVE-2006-4305");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1190 security update');
 script_set_attribute(attribute: 'description', value:
'Oliver Karow discovered that the WebDBM frontend of the MaxDB database
performs insufficient sanitising of requests passed to it, which might
lead to the execution of arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 7.5.00.24-4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1190');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your maxdb-7.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1190] DSA-1190-1 maxdb-7.5.00");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1190-1 maxdb-7.5.00");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libsqldbc7.5.00', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'libsqldbc7.5.00-dev', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'libsqlod7.5.00', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'libsqlod7.5.00-dev', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'maxdb-dbanalyzer', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'maxdb-dbmcli', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'maxdb-loadercli', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'maxdb-lserver', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'maxdb-server', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'maxdb-server-7.5.00', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'maxdb-server-dbg-7.5.00', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'maxdb-sqlcli', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'maxdb-webtools', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'python-maxdb', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'python-maxdb-loader', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'python2.3-maxdb', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'python2.3-maxdb-loader', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'python2.4-maxdb', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'python2.4-maxdb-loader', release: '3.1', reference: '7.5.00.24-4');
deb_check(prefix: 'maxdb-7.5.00', release: '3.1', reference: '7.5.00.24-4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
