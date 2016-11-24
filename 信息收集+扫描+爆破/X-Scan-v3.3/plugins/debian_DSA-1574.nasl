# This script was automatically generated from the dsa-1574
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(32308);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "1574");
 script_cve_id("CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1574 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Icedove mail
client, an unbranded version of the Thunderbird client.  The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2008-1233
    <q>moz_bug_r_a4</q> discovered that variants of CVE-2007-3738 and
    CVE-2007-5338 allow the execution of arbitrary code through
    XPCNativeWrapper.
CVE-2008-1234
    <q>moz_bug_r_a4</q> discovered that insecure handling of event
    handlers could lead to cross-site scripting.
CVE-2008-1235
    Boris Zbarsky, Johnny Stenback and <q>moz_bug_r_a4</q> discovered
    that incorrect principal handling could lead to cross-site
    scripting and the execution of arbitrary code.
CVE-2008-1236
    Tom Ferris, Seth Spitzer, Martin Wargers, John Daggett and Mats
    Palmgren discovered crashes in the layout engine, which might
    allow the execution of arbitrary code.
CVE-2008-1237
    <q>georgi</q>, <q>tgirmann</q> and Igor Bukanov discovered crashes in the
    Javascript engine, which might allow the execution of arbitrary
    code.
For the stable distribution (etch), these problems have been fixed in
version 1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1574');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your icedove packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1574] DSA-1574-1 icedove");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1574-1 icedove");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'icedove', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'icedove-dbg', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'icedove-dev', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'icedove-gnome-support', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'icedove-inspector', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'icedove-typeaheadfind', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'mozilla-thunderbird', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'mozilla-thunderbird-dev', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'mozilla-thunderbird-inspector', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'mozilla-thunderbird-typeaheadfind', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'thunderbird', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'thunderbird-dbg', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'thunderbird-dev', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'thunderbird-gnome-support', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'thunderbird-inspector', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
deb_check(prefix: 'thunderbird-typeaheadfind', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080417a-0etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
