# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-09.xml
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
 script_id(35084);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200812-09");
 script_cve_id("CVE-2008-2235");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-09
(OpenSC: Insufficient protection of smart card PIN)


    Chaskiel M Grundman reported that OpenSC uses weak permissions (ADMIN
    file control information of 00) for the 5015 directory on smart cards
    and USB crypto tokens running Siemens CardOS M4.
  
Impact

    A physically proximate attacker can exploit this vulnerability to
    change the PIN on a smart card and use it for authentication, leading
    to privilege escalation.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenSC users should upgrade to the latest version, and then check
    and update their smart cards:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/opensc-0.11.6"
    # pkcs15-tool --test-update
    # pkcs15-tool --test-update --update
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2235');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-09] OpenSC: Insufficient protection of smart card PIN');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSC: Insufficient protection of smart card PIN');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/opensc", unaffected: make_list("ge 0.11.6"), vulnerable: make_list("lt 0.11.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
