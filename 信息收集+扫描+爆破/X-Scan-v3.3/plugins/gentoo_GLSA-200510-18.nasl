# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-18.xml
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
 script_id(20080);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200510-18");
 script_cve_id("CVE-2005-2978");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-18
(Netpbm: Buffer overflow in pnmtopng)


    RedHat reported that pnmtopng is vulnerable to a buffer overflow.
  
Impact

    An attacker could craft a malicious PNM file and entice a user to run
    pnmtopng on it, potentially resulting in the execution of arbitrary
    code with the permissions of the user running pnmtopng.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Netpbm users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose media-libs/netpbm
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2978');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-18] Netpbm: Buffer overflow in pnmtopng');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Netpbm: Buffer overflow in pnmtopng');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/netpbm", unaffected: make_list("ge 10.29", "rge 10.26.32", "rge 10.26.33", "rge 10.26.42", "rge 10.26.43", "rge 10.26.44", "rge 10.26.48", "rge 10.26.49", "rge 10.26.52", "rge 10.26.53", "rge 10.26.59", "rge 10.26.61"), vulnerable: make_list("lt 10.29")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
