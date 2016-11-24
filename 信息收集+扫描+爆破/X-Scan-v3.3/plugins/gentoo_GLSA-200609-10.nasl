# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(22355);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200609-10");
 script_cve_id("CVE-2006-4674", "CVE-2006-4675", "CVE-2006-4679");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200609-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200609-10
(DokuWiki: Arbitrary command execution)


    "rgod" discovered that DokuWiki doesn\'t sanitize the X-FORWARDED-FOR
    HTTP header, allowing the injection of arbitrary contents - such as PHP
    commands - into a file. Additionally, the accessory scripts installed
    in the "bin" DokuWiki directory are vulnerable to directory traversal
    attacks, allowing to copy and execute the previously injected code.
  
Impact

    A remote attacker may execute arbitrary PHP (and thus probably system)
    commands with the permissions of the user running the process serving
    DokuWiki pages.
  
Workaround

    Disable remote access to the "bin" subdirectory of the DokuWiki
    installation. Remove the directory if you don\'t use the scripts in
    there.
  
');
script_set_attribute(attribute:'solution', value: '
    All DokuWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/dokuwiki-20060309d"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4674');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4675');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4679');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200609-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200609-10] DokuWiki: Arbitrary command execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'DokuWiki: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/dokuwiki", unaffected: make_list("ge 20060309d"), vulnerable: make_list("lt 20060309d")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
