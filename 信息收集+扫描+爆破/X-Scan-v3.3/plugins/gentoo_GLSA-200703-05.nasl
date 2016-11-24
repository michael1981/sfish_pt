# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-05.xml
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
 script_id(24772);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200703-05");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-05
(Mozilla Suite: Multiple vulnerabilities)


    Several vulnerabilities ranging from code execution with elevated
    privileges to information leaks affect the Mozilla Suite.
  
Impact

    A remote attacker could entice a user to browse to a specially crafted
    website or open a specially crafted mail that could trigger some of the
    vulnerabilities, potentially allowing execution of arbitrary code,
    denials of service, information leaks, or cross-site scripting attacks
    leading to the robbery of cookies of authentication credentials.
  
Workaround

    Most of the issues, but not all of them, can be prevented by disabling
    the HTML rendering in the mail client and JavaScript on every
    application.
  
');
script_set_attribute(attribute:'solution', value: '
    The Mozilla Suite is no longer supported and has been masked after some
    necessary changes on all the other ebuilds which used to depend on it.
    Mozilla Suite users should unmerge www-client/mozilla or
    www-client/mozilla-bin, and switch to a supported product, like
    SeaMonkey, Thunderbird or Firefox.
    # emerge --unmerge "www-client/mozilla"
    # emerge --unmerge "www-client/mozilla-bin"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mozilla');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-05] Mozilla Suite: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Suite: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/mozilla", unaffected: make_list(), vulnerable: make_list("le 1.7.13")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "www-client/mozilla-bin", unaffected: make_list(), vulnerable: make_list("le 1.7.13")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
