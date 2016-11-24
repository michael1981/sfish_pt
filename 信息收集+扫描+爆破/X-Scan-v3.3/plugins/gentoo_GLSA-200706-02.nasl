# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200706-02.xml
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
 script_id(25452);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200706-02");
 script_cve_id("CVE-2007-1002");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200706-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200706-02
(Evolution: User-assisted execution of arbitrary code)


    Ulf Harnhammar from Secunia Research has discovered a format string
    error in the write_html() function in the file
    calendar/gui/e-cal-component-memo-preview.c.
  
Impact

    A remote attacker could entice a user to open a specially crafted
    shared memo, possibly resulting in the execution of arbitrary code with
    the privileges of the user running Evolution.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Evolution users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/evolution-2.8.3-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1002');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200706-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200706-02] Evolution: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Evolution: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/evolution", unaffected: make_list("ge 2.8.3-r2"), vulnerable: make_list("lt 2.8.3-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
