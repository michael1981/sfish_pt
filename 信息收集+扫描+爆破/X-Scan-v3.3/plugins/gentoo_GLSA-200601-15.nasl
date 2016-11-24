# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-15.xml
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
 script_id(20823);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200601-15");
 script_cve_id("CVE-2005-3280");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200601-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200601-15
(Paros: Default administrator password)


    Andrew Christensen discovered that in older versions of Paros the
    database component HSQLDB is installed with an empty password for the
    database administrator "sa".
  
Impact

    Since the database listens globally by default, an attacker can
    connect and issue arbitrary commands, including execution of binaries
    installed on the host.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Paros users should upgrade to the latest version:
    # emerge --snyc
    # emerge --ask --oneshot --verbose ">=net-proxy/paros-3.2.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3280');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200601-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200601-15] Paros: Default administrator password');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Paros: Default administrator password');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-proxy/paros", unaffected: make_list("gt 3.2.5"), vulnerable: make_list("le 3.2.5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
