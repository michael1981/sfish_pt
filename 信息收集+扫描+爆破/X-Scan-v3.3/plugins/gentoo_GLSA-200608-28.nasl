# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-28.xml
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
 script_id(22290);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200608-28");
 script_cve_id("CVE-2006-4020");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200608-28 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200608-28
(PHP: Arbitary code execution)


    The sscanf() PHP function contains an array boundary error that can be
    exploited to dereference a null pointer. This can possibly allow the
    bypass of the safe mode protection by executing arbitrary code.
  
Impact

    A remote attacker might be able to exploit this vulnerability in PHP
    applications making use of the sscanf() function, potentially resulting
    in the execution of arbitrary code or the execution of scripted
    contents in the context of the affected site.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHP 4.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/php-4.4.3-r1"
    All PHP 5.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/php-5.1.4-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4020');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200608-28.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200608-28] PHP: Arbitary code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Arbitary code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/php", unaffected: make_list("rge 4.4.3-r1", "rge 4.4.4-r4", "rge 4.4.6", "rge 4.4.7", "rge 4.4.8_pre20070816", "ge 5.1.4-r6"), vulnerable: make_list("lt 5.1.4-r6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
