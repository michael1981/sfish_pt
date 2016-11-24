# This script was automatically generated from the dsa-1399
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(27629);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1399");
 script_cve_id("CVE-2007-1659", "CVE-2007-1660", "CVE-2007-1661", "CVE-2007-1662", "CVE-2007-4766", "CVE-2007-4767", "CVE-2007-4768");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1399 security update');
 script_set_attribute(attribute: 'description', value:
'Tavis Ormandy of the Google Security Team has discovered several
security issues in PCRE, the Perl-Compatible Regular Expression library,
which potentially allow attackers to execute arbitrary code by compiling
specially crafted regular expressions.


Version 7.0 of the PCRE library featured a major rewrite of the regular
expression compiler, and it was deemed infeasible to backport the
security fixes in version 7.3 to the versions in Debian\'s stable and
oldstable distributions (6.7 and 4.5, respectively).  Therefore, this
update is based on version 7.4 (which includes the security bug fixes of
the 7.3 version, plus several regression fixes), with special patches to
improve the compatibility with the older versions.  As a result, extra
care is necessary when applying this update.


The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2007-1659
    
    Unmatched \\Q\\E sequences with orphan \\E codes can cause the compiled
    regex to become desynchronized, resulting in corrupt bytecode that may
    result in multiple exploitable conditions.
    
CVE-2007-1660
    
    Multiple forms of character classes had their sizes miscalculated on
    initial passes, resulting in too little memory being allocated.
    
CVE-2007-1661
    
    Multiple patterns of the form  \\X?\\d or \\P{L}?\\d in non-UTF-8 mode
    could backtrack before the start of the string, possibly leaking
    information from the address space, or causing a crash by reading out
    of bounds.
    
CVE-2007-1662
    
    A number of routines can be fooled into reading past the end of a
    string looking for unmatched parentheses or brackets, resulting in a
    denial of service.
    
CVE-2007-4766
    
    Multiple integer overflows in the processing of escape sequences could
    result in heap overflows or out of bounds reads/writes.
    
CVE-2007-4767
    
    Multiple infinite loops and heap overflows were discovered in the
    handling of \\P and \\P{x} sequences, where the length of these
    non-standard operations was mishandled.
    
CVE-2007-4768
    
    Character classes containing a lone unicode sequence were incorrectly
    optimised, resulting in a heap overflow.
    

For the old stable distribution (sarge), these problems have been fixed in
version 4.5+7.4-1.


For the stable distribution (etch), these problems have been fixed in
version 6.7+7.4-2.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1399');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2007/dsa-1399
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1399] DSA-1399-1 pcre3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1399-1 pcre3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpcre3', release: '3.1', reference: '4.5+7.4-1');
deb_check(prefix: 'libpcre3-dev', release: '3.1', reference: '4.5+7.4-1');
deb_check(prefix: 'pcregrep', release: '3.1', reference: '4.5+7.4-1');
deb_check(prefix: 'pgrep', release: '3.1', reference: '4.5+7.4-1');
deb_check(prefix: 'libpcre3', release: '4.0', reference: '6.7+7.4-2');
deb_check(prefix: 'libpcre3-dev', release: '4.0', reference: '6.7+7.4-2');
deb_check(prefix: 'libpcrecpp0', release: '4.0', reference: '6.7+7.4-2');
deb_check(prefix: 'pcregrep', release: '4.0', reference: '6.7+7.4-2');
deb_check(prefix: 'pcre3', release: '4.0', reference: '6.7+7.4-2');
deb_check(prefix: 'pcre3', release: '3.1', reference: '4.5+7.4-1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
