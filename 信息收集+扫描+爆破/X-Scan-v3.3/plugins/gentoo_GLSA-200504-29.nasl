# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-29.xml
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
 script_id(18168);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200504-29");
 script_cve_id("CVE-2005-1391");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-29 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-29
(Pound: Buffer overflow vulnerability)


    Steven Van Acker has discovered a buffer overflow vulnerability in the
    "add_port()" function in Pound.
  
Impact

    A remote attacker could send a request for an overly long hostname
    parameter, which could lead to the remote execution of arbitrary code
    with the rights of the Pound daemon process (by default, Gentoo uses
    the "nobody" user to run the Pound daemon).
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Pound users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/pound-1.8.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.apsis.ch/pound/pound_list/archive/2005/2005-04/1114516112000');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1391');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-29.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-29] Pound: Buffer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pound: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/pound", unaffected: make_list("ge 1.8.3"), vulnerable: make_list("lt 1.8.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
