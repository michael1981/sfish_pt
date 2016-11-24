# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200401-03.xml
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
 script_id(14443);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200401-03");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200401-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200401-03
(Apache mod_python Denial of Service vulnerability)


    The Apache Foundation has reported that mod_python may be prone to
    Denial of Service attacks when handling a malformed
    query. Mod_python 2.7.9 was released to fix the vulnerability,
    however, because the vulnerability has not been fully fixed,
    version 2.7.10 has been released.
    Users of mod_python 3.0.4 are not affected by this vulnerability.
  
Impact

    Although there are no known public exploits known for this
    exploit, users are recommended to upgrade mod_python to ensure the
    security of their infrastructure.
  
Workaround

    Mod_python 2.7.10 has been released to solve this issue; there is
    no immediate workaround.
  
');
script_set_attribute(attribute:'solution', value: '
    All users using mod_python 2.7.9 or below are recommended to
    update their mod_python installation:
    $> emerge sync
    $> emerge -pv ">=www-apache/mod_python-2.7.10"
    $> emerge ">=www-apache/mod_python-2.7.10"
    $> /etc/init.d/apache restart
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Low');
script_set_attribute(attribute: 'see_also', value: 'http://www.modpython.org/pipermail/mod_python/2004-January/014879.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200401-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200401-03] Apache mod_python Denial of Service vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache mod_python Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apache/mod_python", unaffected: make_list("ge 2.7.10"), vulnerable: make_list("lt 2.7.10")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
