# This script was automatically generated from the dsa-1696
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35313);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1696");
 script_cve_id("CVE-2008-0016", "CVE-2008-1380", "CVE-2008-3835", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1696 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Icedove
mail client, an unbranded version of the Thunderbird mail client. The
Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2008-0016
   Justin Schuh, Tom Cross and Peter Williams discovered a buffer
   overflow in the parser for UTF-8 URLs, which may lead to the execution
   of arbitrary code. (MFSA 2008-37)
CVE-2008-1380
   It was discovered that crashes in the Javascript engine could
   potentially lead to the execution of arbitrary code. (MFSA 2008-20)
CVE-2008-3835
   "moz_bug_r_a4" discovered that the same-origin check in
   nsXMLDocument::OnChannelRedirect() could be bypassed. (MFSA 2008-38)
CVE-2008-4058
   "moz_bug_r_a4" discovered a vulnerability which can result in
   Chrome privilege escalation through XPCNativeWrappers. (MFSA 2008-41)
CVE-2008-4059
   "moz_bug_r_a4" discovered a vulnerability which can result in
   Chrome privilege escalation through XPCNativeWrappers. (MFSA 2008-41)
CVE-2008-4060
   Olli Pettay and "moz_bug_r_a4" discovered a Chrome privilege
   escalation vulnerability in XSLT handling. (MFSA 2008-41)
CVE-2008-4061
   Jesse Ruderman discovered a crash in the layout engine, which might
   allow the execution of arbitrary code. (MFSA 2008-42)
CVE-2008-4062
   Igor Bukanov, Philip Taylor, Georgi Guninski and Antoine Labour
   discovered crashes in the Javascript engine, which might allow the
   execution of arbitrary code. (MFSA 2008-42)
CVE-2008-4065
   Dave Reed discovered that some Unicode byte order marks are
   stripped from Javascript code before execution, which can result in
   code being executed, which were otherwise part of a quoted string.
   (MFSA 2008-43)
CVE-2008-4067
   It was discovered that a directory traversal allows attackers to
   read arbitrary files via a certain character. (MFSA 2008-44)
CVE-2008-4068
   It was discovered that a directory traversal allows attackers to
   bypass security restrictions and obtain sensitive information.
   (MFSA 2008-44)
CVE-2008-4070
   It was discovered that a buffer overflow could be triggered via a
   long header in a news article, which could lead to arbitrary code
   execution. (MFSA 2008-46)
CVE-2008-4582
   Liu Die Yu and Boris Zbarsky discovered an information leak through
   local shortcut files. (MFSA 2008-47, MFSA 2008-59)
CVE-2008-5012
   Georgi Guninski, Michal Zalewski and Chris Evan discovered that
   the canvas element could be used to bypass same-origin
   restrictions. (MFSA 2008-48)
CVE-2008-5014
   Jesse Ruderman discovered that a programming error in the
   window.__proto__.__proto__ object could lead to arbitrary code
   execution. (MFSA 2008-50)
CVE-2008-5017
   It was discovered that crashes in the layout engine could lead to
   arbitrary code execution. (MFSA 2008-52)
CVE-2008-5018
   It was discovered that crashes in the Javascript engine could lead to
   arbitrary code execution. (MFSA 2008-52)
CVE-2008-5021
   It was discovered that a crash in the nsFrameManager might lead to
   the execution of arbitrary code. (MFSA 2008-55)
CVE-2008-5022
   "moz_bug_r_a4" discovered that the same-origin check in
   nsXMLHttpRequest
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1696');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your icedove packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1696] DSA-1696-1 icedove");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1696-1 icedove");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'icedove', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'icedove-dbg', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'icedove-dev', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'icedove-gnome-support', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'icedove-inspector', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'icedove-typeaheadfind', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'mozilla-thunderbird', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'mozilla-thunderbird-dev', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'mozilla-thunderbird-inspector', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'mozilla-thunderbird-typeaheadfind', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'thunderbird', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'thunderbird-dbg', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'thunderbird-dev', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'thunderbird-gnome-support', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'thunderbird-inspector', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
deb_check(prefix: 'thunderbird-typeaheadfind', release: '4.0', reference: '1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
