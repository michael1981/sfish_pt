# This script was automatically generated from the dsa-1669
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(34938);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "1669");
 script_cve_id("CVE-2008-0016", "CVE-2008-0017", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1669 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications. The Common Vulnerabilities
and Exposures project identifies the following problems:
CVE-2008-0016
   Justin Schuh, Tom Cross and Peter Williams discovered a buffer
   overflow in the parser for UTF-8 URLs, which may lead to the
   execution of arbitrary code.
CVE-2008-3835
   "moz_bug_r_a4" discovered that the same-origin check in
   nsXMLDocument::OnChannelRedirect() could by bypassed.
CVE-2008-3836
   "moz_bug_r_a4" discovered that several vulnerabilities in
   feedWriter could lead to Chrome privilege escalation.
CVE-2008-3837
   Paul Nickerson discovered that an attacker could move windows
   during a mouse click, resulting in unwanted action triggered by
   drag-and-drop.
CVE-2008-4058
   "moz_bug_r_a4" discovered a vulnerability which can result in
   Chrome privilege escalation through XPCNativeWrappers.
CVE-2008-4059
   "moz_bug_r_a4" discovered a vulnerability which can result in
   Chrome privilege escalation through XPCNativeWrappers.
CVE-2008-4060
   Olli Pettay and "moz_bug_r_a4" discovered a Chrome privilege
   escalation vulnerability in XSLT handling.
CVE-2008-4061
   Jesse Ruderman discovered a crash in the layout engine, which might
   allow the execution of arbitrary code.
CVE-2008-4062
   Igor Bukanov, Philip Taylor, Georgi Guninski and Antoine Labour
   discovered crashes in the Javascript engine, which might allow the
   execution of arbitrary code.
CVE-2008-4065
   Dave Reed discovered that some Unicode byte order marks are
   stripped from Javascript code before execution, which can result in
   code being executed, which were otherwise part of a quoted string.
CVE-2008-4066
   Gareth Heyes discovered that some Unicode surrogate characters are
   ignored by the HTML parser.
CVE-2008-4067
   Boris Zbarsky discovered that resource: URls allow directory
   traversal when using URL-encoded slashes.
CVE-2008-4068
   Georgi Guninski discovered that resource: URLs could bypass local
   access restrictions.
CVE-2008-4069
   Billy Hoffman discovered that the XBM decoder could reveal
   uninitialised memory.
CVE-2008-4582
   Liu Die Yu discovered an information leak through local shortcut
   files.
CVE-2008-5012
   Georgi Guninski, Michal Zalewski and Chris Evan discovered that
   the canvas element could be used to bypass same-origin
   restrictions.
CVE-2008-5013
   It was discovered that insufficient checks in the Flash plugin glue
   code could lead to arbitrary code execution.
CVE-2008-5014
   Jesse Ruderman discovered that a programming error in the
   window.__proto__.__proto__ object could lead to arbitrary code
   execution.
CVE-2008-5017
   It was discovered that crashes in the layout engine could lead to
   arbitrary code execution.
CVE-2008-5018
   It was discovered that crashes in the Javascript engine could lead to
   arbitrary code execution.
CVE-2008-0017
   Justin Schuh discovered that a buffer overflow in http-index-format
   parser could lead to arbitrary code execution.
CVE-2008-5021
   It was discovered that a crash in the nsFrameManager might lead to
   the execution of arbitrary
[...]');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1669');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your xulrunner packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1669] DSA-1669-1 xulrunner");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1669-1 xulrunner");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
