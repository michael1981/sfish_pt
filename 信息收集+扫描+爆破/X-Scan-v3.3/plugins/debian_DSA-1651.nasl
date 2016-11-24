# This script was automatically generated from the dsa-1651
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34387);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1651");
 script_cve_id("CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1651 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in the interpreter for
the Ruby language, which may lead to denial of service and other
security problems. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2008-3655
    Keita Yamaguchi discovered that several safe level restrictions
    are insufficiently enforced.
CVE-2008-3656
    Christian Neukirchen discovered that the WebRick module uses
    inefficient algorithms for HTTP header splitting, resulting in
    denial of service through resource exhaustion.
CVE-2008-3657
    It was discovered that the dl module doesn\'t perform taintness
    checks.
CVE-2008-3790
    Luka Treiber and Mitja Kolsek discovered that recursively nested
    XML entities can lead to denial of service through resource
    exhaustion in rexml.
CVE-2008-3905
    Tanaka Akira discovered that the resolv module uses sequential
    transaction IDs and a fixed source port for DNS queries, which
    makes it more vulnerable to DNS spoofing attacks.
For the stable distribution (etch), these problems have been fixed in
version 1.8.5-4etch3. Packages for arm will be provided later.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1651');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your ruby1.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1651] DSA-1651-1 ruby1.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1651-1 ruby1.8");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'irb1.8', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'libdbm-ruby1.8', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'libgdbm-ruby1.8', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'libopenssl-ruby1.8', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'libreadline-ruby1.8', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'libruby1.8', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'libruby1.8-dbg', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'libtcltk-ruby1.8', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'rdoc1.8', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'ri1.8', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'ruby1.8', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'ruby1.8-dev', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'ruby1.8-elisp', release: '4.0', reference: '1.8.5-4etch3');
deb_check(prefix: 'ruby1.8-examples', release: '4.0', reference: '1.8.5-4etch3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
