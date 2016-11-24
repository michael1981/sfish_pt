# This script was automatically generated from the dsa-925
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22791);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "925");
 script_cve_id("CVE-2005-3310", "CVE-2005-3415", "CVE-2005-3416", "CVE-2005-3417", "CVE-2005-3418", "CVE-2005-3419", "CVE-2005-3420");
 script_bugtraq_id(15170, 15243);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-925 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in phpBB, a fully
featured and skinnable flat webforum. The Common Vulnerabilities
and Exposures project identifies the following problems:
CVE-2005-3310
    Multiple interpretation errors allow remote authenticated users to
    inject arbitrary web script when remote avatars and avatar
    uploading are enabled.
CVE-2005-3415
    phpBB allows remote attackers to bypass protection mechanisms that
    deregister global variables that allows attackers to manipulate
    the behaviour of phpBB.
CVE-2005-3416
    phpBB allows remote attackers to bypass security checks when
    register_globals is enabled and the session_start function has not
    been called to handle a session.
CVE-2005-3417
    phpBB allows remote attackers to modify global variables and
    bypass security mechanisms.
CVE-2005-3418
    Multiple cross-site scripting (XSS) vulnerabilities allow remote
    attackers to inject arbitrary web scripts.
CVE-2005-3419
    An SQL injection vulnerability allows remote attackers to execute
    arbitrary SQL commands.
CVE-2005-3420
    phpBB allows remote attackers to modify regular expressions and
    execute PHP code via the signature_bbcode_uid parameter.
CVE-2005-3536
    Missing input sanitising of the topic type allows remote attackers
    to inject arbitrary SQL commands.
CVE-2005-3537
    Missing request validation permitted remote attackers to edit
    private messages of other users.
The old stable distribution (woody) does not contain phpbb2 packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.0.13+1-6sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-925');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your phpbb2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA925] DSA-925-1 phpbb2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-925-1 phpbb2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13-6sarge2');
deb_check(prefix: 'phpbb2-conf-mysql', release: '3.1', reference: '2.0.13-6sarge2');
deb_check(prefix: 'phpbb2-languages', release: '3.1', reference: '2.0.13-6sarge2');
deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13+1-6sarge2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
