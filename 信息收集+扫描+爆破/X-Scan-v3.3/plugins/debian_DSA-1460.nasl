# This script was automatically generated from the dsa-1460
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29937);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1460");
 script_cve_id("CVE-2007-3278", "CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1460 security update');
 script_set_attribute(attribute: 'description', value:
'Several local vulnerabilities have been discovered in PostgreSQL, an
object-relational SQL database. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2007-3278
    
    It was discovered that the DBLink module performed insufficient
    credential validation. This issue is also tracked as CVE-2007-6601,
    since the initial upstream fix was incomplete.
    
CVE-2007-4769
    
    Tavis Ormandy and Will Drewry discovered that a bug in the handling
    of back-references inside the regular expressions engine could lead
    to an out of bounds read, resulting in a crash. This constitutes only
    a security problem if an application using PostgreSQL processes
    regular expressions from untrusted sources.
    
CVE-2007-4772
    
    Tavis Ormandy and Will Drewry discovered that the optimizer for regular
    expression could be tricked into an infinite loop, resulting in denial
    of service. This constitutes only a security problem if an application
    using PostgreSQL processes regular expressions from untrusted sources.
    
CVE-2007-6067
    
    Tavis Ormandy and Will Drewry discovered that the optimizer for regular
    expression could be tricked massive resource consumption. This
    constitutes only a security problem if an application using PostgreSQL
    processes regular expressions from untrusted sources.
    
CVE-2007-6600
    
    Functions in index expressions could lead to privilege escalation. For
    a more in depth explanation please see the upstream announce available
    at http://www.postgresql.org/about/news.905.
    

The old stable distribution (sarge), doesn\'t contain postgresql-8.1.


For the stable distribution (etch), these problems have been fixed in version
postgresql-8.1 8.1.11-0etch1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1460');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your postgresql-8.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1460] DSA-1460-1 postgresql-8.1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1460-1 postgresql-8.1");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libecpg-compat2', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'libecpg-dev', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'libecpg5', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'libpgtypes2', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'libpq-dev', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'libpq4', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'postgresql-8.1', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'postgresql-client-8.1', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'postgresql-contrib-8.1', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'postgresql-doc-8.1', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'postgresql-plperl-8.1', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'postgresql-plpython-8.1', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'postgresql-pltcl-8.1', release: '4.0', reference: '8.1.11-0etch1');
deb_check(prefix: 'postgresql-server-dev-8.1', release: '4.0', reference: '8.1.11-0etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
