# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-23.xml
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
 script_id(17128);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200502-23");
 script_cve_id("CVE-2005-0011");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-23
(KStars: Buffer overflow in fliccd)


    Erik Sjolund discovered a buffer overflow in fliccd which is part
    of the INDI support in KStars.
  
Impact

    An attacker could exploit this vulnerability to execute code with
    elevated privileges. If fliccd does not run as daemon remote
    exploitation of this vulnerability is not possible. KDE as shipped by
    Gentoo does not start the daemon in the default installation.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All KStars users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdeedu-3.3.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0011');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-23] KStars: Buffer overflow in fliccd');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KStars: Buffer overflow in fliccd');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kdeedu", unaffected: make_list("ge 3.3.2-r1"), vulnerable: make_list("lt 3.3.2-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
