# This script was automatically generated from the dsa-647
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16214);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "647");
 script_cve_id("CVE-2005-0004");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-647 security update');
 script_set_attribute(attribute: 'description', value:
'Javier Fernandez-Sanguino Peña from the Debian Security Audit Project
discovered a temporary file vulnerability in the mysqlaccess script of
MySQL that could allow an unprivileged user to let root overwrite
arbitrary files via a symlink attack and could also could unveil the
contents of a temporary file which might contain sensitive
information.
For the stable distribution (woody) this problem has been fixed in
version 3.23.49-8.9.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-647');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA647] DSA-647-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-647-1 mysql");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.9');
deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.9');
deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.9');
deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.9');
deb_check(prefix: 'mysql-doc', release: '3.0', reference: '3.23.49-8.5');
deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.9');
deb_check(prefix: 'mysql', release: '3.0', reference: '3.23.49-8.9');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
