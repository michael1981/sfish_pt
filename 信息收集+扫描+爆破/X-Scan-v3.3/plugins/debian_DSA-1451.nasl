# This script was automatically generated from the dsa-1451
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29860);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1451");
 script_cve_id("CVE-2007-3781", "CVE-2007-5969", "CVE-2007-6304");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1451 security update');
 script_set_attribute(attribute: 'description', value:
'Several local/remote vulnerabilities have been discovered in the MySQL
database server. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2007-3781
    
    It was discovered that the privilege validation for the source table
    of CREATE TABLE LIKE statements was insufficiently enforced, which
    might lead to information disclosure. This is only exploitable by
    authenticated users.
    
CVE-2007-5969
    
    It was discovered that symbolic links were handled insecurely during
    the creation of tables with DATA DIRECTORY or INDEX DIRECTORY
    statements, which might lead to denial of service by overwriting
    data. This is only exploitable by authenticated users.
    
CVE-2007-6304
    
    It was discovered that queries to data in a FEDERATED table can
    lead to a crash of the local database server, if the remote server
    returns information with less columns than expected, resulting in
    denial of service.
    

The old stable distribution (sarge) doesn\'t contain mysql-dfsg-5.0.


For the stable distribution (etch), these problems have been fixed in
version 5.0.32-7etch4.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1451');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mysql-dfsg-5.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1451] DSA-1451-1 mysql-dfsg-5.0");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1451-1 mysql-dfsg-5.0");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmysqlclient15-dev', release: '4.0', reference: '5.0.32-7etch4');
deb_check(prefix: 'libmysqlclient15off', release: '4.0', reference: '5.0.32-7etch4');
deb_check(prefix: 'mysql-client', release: '4.0', reference: '5.0.32-7etch4');
deb_check(prefix: 'mysql-client-5.0', release: '4.0', reference: '5.0.32-7etch4');
deb_check(prefix: 'mysql-common', release: '4.0', reference: '5.0.32-7etch4');
deb_check(prefix: 'mysql-server', release: '4.0', reference: '5.0.32-7etch4');
deb_check(prefix: 'mysql-server-4.1', release: '4.0', reference: '5.0.32-7etch4');
deb_check(prefix: 'mysql-server-5.0', release: '4.0', reference: '5.0.32-7etch4');
deb_check(prefix: 'mysql-dfsg-5.0', release: '4.0', reference: '5.0.32-7etch4');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
