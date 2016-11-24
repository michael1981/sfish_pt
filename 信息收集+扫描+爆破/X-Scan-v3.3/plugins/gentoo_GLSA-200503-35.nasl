# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-35.xml
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
 script_id(17665);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200503-35");
 script_cve_id("CVE-2005-0913");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-35 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-35
(Smarty: Template vulnerability)


    A vulnerability has been discovered within the regex_replace modifier
    of the Smarty templates when allowing access to untrusted users.
    Furthermore, it was possible to call functions from {if} statements and
    {math} functions.
  
Impact

    These issues may allow a remote attacker to bypass the "template
    security" feature of Smarty, and execute arbitrary PHP code.
  
Workaround

    Do not grant template access to untrusted users.
  
');
script_set_attribute(attribute:'solution', value: '
    All Smarty users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/smarty-2.6.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://smarty.php.net/misc/NEWS');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0913');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-35.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-35] Smarty: Template vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Smarty: Template vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-php/smarty", unaffected: make_list("ge 2.6.9"), vulnerable: make_list("lt 2.6.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
