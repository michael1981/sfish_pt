# This script was automatically generated from the dsa-1697
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35314);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1697");
 script_cve_id("CVE-2008-0016", "CVE-2008-0017", "CVE-2008-0304", "CVE-2008-2785", "CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1697 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Iceape an
unbranded version of the Seamonkey internet suite. The Common
Vulnerabilities and Exposures project identifies the following problems:
CVE-2008-0016
   Justin Schuh, Tom Cross and Peter Williams discovered a buffer
   overflow in the parser for UTF-8 URLs, which may lead to the
   execution of arbitrary code. (MFSA 2008-37)
CVE-2008-0304
    It was discovered that a buffer overflow in MIME decoding can lead
    to the execution of arbitrary code. (MFSA 2008-26)
CVE-2008-2785
    It was discovered that missing boundary checks on a reference
    counter for CSS objects can lead to the execution of arbitrary code.
    (MFSA 2008-34)
CVE-2008-2798
    Devon Hubbard, Jesse Ruderman and Martijn Wargers discovered
    crashes in the layout engine, which might allow the execution of
    arbitrary code. (MFSA 2008-21)
CVE-2008-2799
    Igor Bukanov, Jesse Ruderman and Gary Kwong discovered crashes in
    the Javascript engine, which might allow the execution of arbitrary
    code. (MFSA 2008-21)
CVE-2008-2800
    "moz_bug_r_a4" discovered several cross-site scripting vulnerabilities.
    (MFSA 2008-22)
CVE-2008-2801
    Collin Jackson and Adam Barth discovered that Javascript code
    could be executed in the context or signed JAR archives. (MFSA 2008-23)
CVE-2008-2802
    "moz_bug_r_a4" discovered that XUL documements can escalate
    privileges by accessing the pre-compiled "fastload" file.
    (MFSA 2008-24)
CVE-2008-2803
    "moz_bug_r_a4" discovered that missing input sanitising in the
    mozIJSSubScriptLoader.loadSubScript() function could lead to the
    execution of arbitrary code. Iceape itself is not affected, but
    some addons are. (MFSA 2008-25)
CVE-2008-2805
    Claudio Santambrogio discovered that missing access validation in
    DOM parsing allows malicious web sites to force the browser to
    upload local files to the server, which could lead to information
    disclosure. (MFSA 2008-27)
CVE-2008-2807
    Daniel Glazman discovered that a programming error in the code for
    parsing .properties files could lead to memory content being
    exposed to addons, which could lead to information disclosure.
    (MFSA 2008-29)
CVE-2008-2808
    Masahiro Yamada discovered that file URLs in directory listings
    were insufficiently escaped. (MFSA 2008-30)
CVE-2008-2809
    John G. Myers, Frank Benkstein and Nils Toedtmann discovered that
    alternate names on self-signed certificates were handled
    insufficiently, which could lead to spoofings of secure connections.
    (MFSA 2008-31)
CVE-2008-2810
   It was discovered that URL shortcut files could be used to bypass the
   same-origin restrictions. This issue does not affect current Iceape,
   but might occur with additional extensions installed. (MFSA 2008-32)
CVE-2008-2811
    Greg McManus discovered a crash in the block reflow code, which might
    allow the execution of arbitrary code. (MFSA 2008-33)
CVE-2008-2933
    Billy Rios discovered that passing an URL containing a pipe symbol
    to Iceape can lead to Chrome privilege escalation. (MFSA 2008-35)
CVE-2008-3835
   "moz_bug_r_a4" discovered that 
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1697');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your iceape packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1697] DSA-1697-1 iceape");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1697-1 iceape");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
