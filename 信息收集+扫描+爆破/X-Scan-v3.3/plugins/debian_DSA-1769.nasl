# This script was automatically generated from the dsa-1769
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36142);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1769");
 script_cve_id("CVE-2006-2426", "CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733", "CVE-2009-0793", "CVE-2009-1093", "CVE-2009-1094");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1769 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been identified in OpenJDK, an
implementation of the Java SE platform.
CVE-2006-2426
    Creation of large, temporary fonts could use up available disk space,
    leading to a denial of service condition.
    Several vulnerabilities existed in the embedded LittleCMS library,
    exploitable through crafted images: a memory leak, resulting in a
    denial of service condition (CVE-2009-0581), heap-based buffer
    overflows, potentially allowing arbitrary code execution
    (CVE-2009-0723, CVE-2009-0733), and a null-pointer dereference,
    leading to denial of service (CVE-2009-0793).
CVE-2009-1093
    The LDAP server implementation (in com.sun.jdni.ldap) did not properly
    close sockets if an error was encountered, leading to a
    denial-of-service condition.
CVE-2009-1094
    The LDAP client implementation (in com.sun.jdni.ldap) allowed
    malicious LDAP servers to execute arbitrary code on the client.
CVE-2008-5153
    The HTTP server implementation (sun.net.httpserver) contained an
    unspecified denial of service vulnerability.
    Several issues in Java Web Start have been addressed. The Debian packages
    currently do not support Java Web Start, so these issues are not
    directly exploitable, but the relevant code has been updated
    nevertheless.
For the stable distribution (lenny), these problems have been fixed in
version 9.1+lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1769');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your openjdk-6 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1769] DSA-1769-1 openjdk-6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1769-1 openjdk-6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'openjdk-6-dbg', release: '5.0', reference: '6b11-9.1+lenny2');
deb_check(prefix: 'openjdk-6-demo', release: '5.0', reference: '6b11-9.1+lenny2');
deb_check(prefix: 'openjdk-6-doc', release: '5.0', reference: '6b11-9.1+lenny2');
deb_check(prefix: 'openjdk-6-jdk', release: '5.0', reference: '6b11-9.1+lenny2');
deb_check(prefix: 'openjdk-6-jre', release: '5.0', reference: '6b11-9.1+lenny2');
deb_check(prefix: 'openjdk-6-jre-headless', release: '5.0', reference: '6b11-9.1+lenny2');
deb_check(prefix: 'openjdk-6-jre-lib', release: '5.0', reference: '6b11-9.1+lenny2');
deb_check(prefix: 'openjdk-6-source', release: '5.0', reference: '6b11-9.1+lenny2');
deb_check(prefix: 'openjdk-6', release: '5.0', reference: '9.1+lenny2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
