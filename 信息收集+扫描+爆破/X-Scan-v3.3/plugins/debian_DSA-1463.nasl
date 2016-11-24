# This script was automatically generated from the dsa-1463
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(29968);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1463");
 script_cve_id("CVE-2007-3278", "CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1463 security update');
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
    

For the old stable distribution (sarge), some of these problems have been
fixed in version 7.4.7-6sarge6 of the postgresql package. Please note that
the fix for CVE-2007-6600 and for the handling of regular expressions
havn\'t been backported due to the intrusiveness of the fix. We recommend
to upgrade to the stable distribution if these vulnerabilities affect your
setup.


For the stable distribution (etch), these problems have been fixed in
version 7.4.19-0etch1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1463');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your postgresql-7.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1463] DSA-1463-1 postgresql-7.4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1463-1 postgresql-7.4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libecpg-dev', release: '3.1', reference: '7.4.7-6sarge6');
deb_check(prefix: 'libecpg4', release: '3.1', reference: '7.4.7-6sarge6');
deb_check(prefix: 'libpgtcl', release: '3.1', reference: '7.4.7-6sarge6');
deb_check(prefix: 'libpgtcl-dev', release: '3.1', reference: '7.4.7-6sarge6');
deb_check(prefix: 'libpq3', release: '3.1', reference: '7.4.7-6sarge6');
deb_check(prefix: 'postgresql', release: '3.1', reference: '7.4.7-6sarge6');
deb_check(prefix: 'postgresql-client', release: '3.1', reference: '7.4.7-6sarge6');
deb_check(prefix: 'postgresql-contrib', release: '3.1', reference: '7.4.7-6sarge6');
deb_check(prefix: 'postgresql-dev', release: '3.1', reference: '7.4.7-6sarge6');
deb_check(prefix: 'postgresql-doc', release: '3.1', reference: '7.4.7-6sarge6');
deb_check(prefix: 'postgresql-7.4', release: '4.0', reference: '7.4.19-0etch1');
deb_check(prefix: 'postgresql-client-7.4', release: '4.0', reference: '7.4.19-0etch1');
deb_check(prefix: 'postgresql-contrib-7.4', release: '4.0', reference: '7.4.19-0etch1');
deb_check(prefix: 'postgresql-doc-7.4', release: '4.0', reference: '7.4.19-0etch1');
deb_check(prefix: 'postgresql-plperl-7.4', release: '4.0', reference: '7.4.19-0etch1');
deb_check(prefix: 'postgresql-plpython-7.4', release: '4.0', reference: '7.4.19-0etch1');
deb_check(prefix: 'postgresql-pltcl-7.4', release: '4.0', reference: '7.4.19-0etch1');
deb_check(prefix: 'postgresql-server-dev-7.4', release: '4.0', reference: '7.4.19-0etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
