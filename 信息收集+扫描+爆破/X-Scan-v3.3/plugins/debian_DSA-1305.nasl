# This script was automatically generated from the dsa-1305
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25504);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1305");
 script_cve_id("CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1305 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Icedove mail client,
an unbranded version of the Thunderbird client. The Common Vulnerabilities and
Exposures project identifies the following problems:
CVE-2007-1558
    Gatan Leurent discovered a cryptographical weakness in APOP
    authentication, which reduces the required efforts for an MITM attack
    to intercept a password. The update enforces stricter validation, which
    prevents this attack.
CVE-2007-2867
    Boris Zbarsky, Eli Friedman, Georgi Guninski, Jesse Ruderman, Martijn
    Wargers and Olli Pettay discovered crashes in the layout engine, which
    might allow the execution of arbitrary code.
CVE-2007-2868
    Brendan Eich, Igor Bukanov, Jesse Ruderman, <q>moz_bug_r_a4</q> and Wladimir Palant
    discovered crashes in the Javascript engine, which might allow the execution of
    arbitrary code. Generally, enabling Javascript in Icedove is not recommended.
Fixes for the oldstable distribution (sarge) are not available. While there
will be another round of security updates for Mozilla products, Debian doesn\'t
have the resources to backport further security fixes to the old Mozilla
products. You\'re strongly encouraged to upgrade to stable as soon as possible.
For the stable distribution (etch) these problems have been fixed in version
1.5.0.12.dfsg1-0etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1305');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your icedove packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1305] DSA-1305-1 icedove");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1305-1 icedove");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'icedove', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'icedove-dbg', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'icedove-dev', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'icedove-gnome-support', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'icedove-inspector', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'icedove-typeaheadfind', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'mozilla-thunderbird', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'mozilla-thunderbird-dev', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'mozilla-thunderbird-inspector', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'mozilla-thunderbird-typeaheadfind', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'thunderbird', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'thunderbird-dbg', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'thunderbird-dev', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'thunderbird-gnome-support', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'thunderbird-inspector', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
deb_check(prefix: 'thunderbird-typeaheadfind', release: '4.0', reference: '1.5.0.12.dfsg1-0etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
