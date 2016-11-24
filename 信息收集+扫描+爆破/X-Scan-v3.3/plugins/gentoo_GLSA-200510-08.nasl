# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-08.xml
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
 script_id(19978);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200510-08");
 script_cve_id("CVE-2005-2967");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-08
(xine-lib: Format string vulnerability)


    Ulf Harnhammar discovered a format string bug in the routines
    handling CDDB server response contents.
  
Impact

    An attacker could submit malicious information about an audio CD
    to a public CDDB server (or impersonate a public CDDB server). When the
    victim plays this CD on a multimedia frontend relying on xine-lib, it
    could end up executing arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All xine-lib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose media-libs/xine-lib
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2967');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-08] xine-lib: Format string vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-lib: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1.1.0-r5", "rge 1.0.1-r4", "rge 1_rc8-r2"), vulnerable: make_list("lt 1.1.0-r5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
