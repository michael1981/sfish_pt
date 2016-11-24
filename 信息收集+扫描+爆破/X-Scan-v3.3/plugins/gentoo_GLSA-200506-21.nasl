# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-21.xml
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
 script_id(18548);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200506-21");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200506-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200506-21
(Trac: File upload vulnerability)


    Stefan Esser of the Hardened-PHP project discovered that Trac
    fails to validate the "id" parameter when uploading attachments to the
    wiki or the bug tracking system.
  
Impact

    A remote attacker could exploit the vulnerability to upload
    arbitrary files to a directory where the webserver has write access to,
    possibly leading to the execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Trac users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/trac-0.8.4"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.hardened-php.net/advisory-012005.php');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200506-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200506-21] Trac: File upload vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Trac: File upload vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/trac", unaffected: make_list("ge 0.8.4"), vulnerable: make_list("lt 0.8.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
